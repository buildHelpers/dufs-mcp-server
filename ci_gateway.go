package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"
)

// artifactGateway is a narrow CI-only data plane. It does not expose MCP tools,
// Dufs credentials, arbitrary paths, DELETE, or MOVE to the runner.
type artifactGateway struct {
    dufs       *DufsClient
    token      string
    prefix     string
    stagingDir string
    maxBytes   int64
    locks      [64]sync.Mutex
}

func validSegment(s string) bool {
    if len(s) == 0 || len(s) > 100 || s == "." || s == ".." || s[0] == '.' {
        return false
    }
    for _, c := range s {
        if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
            c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
            return false
        }
    }
    return true
}

func validDigest(s string) bool {
    if len(s) != sha256.Size*2 {
        return false
    }
    decoded, err := hex.DecodeString(s)
    return err == nil && hex.EncodeToString(decoded) == s
}

func newArtifactGateway(config Config, token, prefix, stagingDir string, maxBytes int64) (*artifactGateway, error) {
    if len(token) < 32 {
        return nil, fmt.Errorf("CI_ARTIFACT_TOKEN must contain at least 32 characters")
    }
    if !validSegment(prefix) {
        return nil, fmt.Errorf("invalid CI_ARTIFACT_PREFIX")
    }
    if maxBytes <= 0 || maxBytes > 1<<40 {
        return nil, fmt.Errorf("invalid CI_ARTIFACT_MAX_BYTES")
    }
    parsed, err := url.Parse(config.DufsURL)
    if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
        parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
        return nil, fmt.Errorf("invalid DUFS_URL")
    }
    if parsed.Scheme == "http" && !config.AllowInsecure {
        host := parsed.Hostname()
        ip := net.ParseIP(host)
        if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
            return nil, fmt.Errorf("DUFS_URL must use HTTPS outside loopback (or explicitly opt in with DUFS_ALLOW_INSECURE=true)")
        }
    }
    if config.Username == "" || config.Password == "" {
        return nil, fmt.Errorf("CI gateway requires dedicated DUFS_USERNAME and DUFS_PASSWORD")
    }
    if stagingDir == "" {
        stagingDir = os.TempDir()
    }
    info, err := os.Stat(stagingDir)
    if err != nil || !info.IsDir() {
        return nil, fmt.Errorf("CI staging directory must exist")
    }
    client := NewDufsClient(config)
    client.Client.Timeout = 30 * time.Minute
    client.Client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
    return &artifactGateway{dufs: client, token: token, prefix: prefix, stagingDir: stagingDir, maxBytes: maxBytes}, nil
}

func (g *artifactGateway) pathFromRequest(r *http.Request) (string, bool) {
    const base = "/v1/artifacts/"
    if !strings.HasPrefix(r.URL.Path, base) {
        return "", false
    }
    segments := strings.Split(strings.TrimPrefix(r.URL.Path, base), "/")
    if len(segments) != 6 {
        return "", false
    }
    for _, s := range segments {
        if !validSegment(s) {
            return "", false
        }
    }
    return g.prefix + "/" + strings.Join(segments, "/"), true
}

func (g *artifactGateway) authorized(r *http.Request) bool {
    auth := r.Header.Get("Authorization")
    const scheme = "Bearer "
    if !strings.HasPrefix(auth, scheme) {
        return false
    }
    supplied := strings.TrimPrefix(auth, scheme)
    return subtle.ConstantTimeCompare([]byte(supplied), []byte(g.token)) == 1
}

func (g *artifactGateway) do(ctx context.Context, method, path string, body io.Reader, contentLength int64, headers map[string]string) (*http.Response, error) {
    // The path is produced solely from validated ASCII segments or a cryptographically
    // random temporary basename. Caller input never becomes a full URL.
    target := strings.TrimRight(g.dufs.BaseURL, "/") + "/" + strings.TrimPrefix(path, "/")
    req, err := http.NewRequestWithContext(ctx, method, target, body)
    if err != nil {
        return nil, err
    }
    if contentLength >= 0 {
        req.ContentLength = contentLength
    }
    req.SetBasicAuth(g.dufs.Username, g.dufs.Password)
    for k, v := range headers {
        req.Header.Set(k, v)
    }
    return g.dufs.Client.Do(req)
}

func (g *artifactGateway) ensureDirs(ctx context.Context, path string) error {
    parts := strings.Split(path, "/")
    for i := 1; i < len(parts); i++ {
        dir := strings.Join(parts[:i], "/")
        resp, err := g.do(ctx, "MKCOL", dir, nil, 0, nil)
        if err != nil {
            return err
        }
        status := resp.StatusCode
        io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
        resp.Body.Close()
        if status != 201 && status != 200 && status != 204 && status != 405 {
            return fmt.Errorf("dufs directory creation failed: HTTP %d", status)
        }
    }
    return nil
}

func (g *artifactGateway) remoteHash(ctx context.Context, path string) (digest string, exists bool, err error) {
    resp, err := g.do(ctx, "GET", path+"?hash", nil, -1, nil)
    if err != nil {
        return "", false, err
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusNotFound {
        return "", false, nil
    }
    if resp.StatusCode != http.StatusOK {
        return "", false, fmt.Errorf("dufs hash unavailable: HTTP %d (enable --allow-hash)", resp.StatusCode)
    }
    b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
    if err != nil {
        return "", false, err
    }
    digest = strings.ToLower(strings.TrimSpace(string(b)))
    if !validDigest(digest) {
        return "", false, errors.New("dufs did not return a SHA-256 digest")
    }
    return digest, true, nil
}

func (g *artifactGateway) deleteTemp(path string) {
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    resp, err := g.do(ctx, "DELETE", path, nil, -1, nil)
    if err == nil {
        resp.Body.Close()
    }
}

func (g *artifactGateway) slot(path string) *sync.Mutex {
    sum := sha256.Sum256([]byte(path))
    return &g.locks[int(sum[0])%len(g.locks)]
}

func artifactJSON(w http.ResponseWriter, status int, fields map[string]interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-store")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(fields)
}

func artifactError(w http.ResponseWriter, status int, message string) {
    artifactJSON(w, status, map[string]interface{}{"error": message})
}

func (g *artifactGateway) serveHTTP(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("X-Content-Type-Options", "nosniff")
    if r.URL.Path == "/healthz" {
        if r.Method != "GET" {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
        defer cancel()
        resp, err := g.do(ctx, "GET", "__dufs__/health", nil, -1, nil)
        if err != nil {
            artifactError(w, 503, "storage unavailable")
            return
        }
        ok := resp.StatusCode == 200
        resp.Body.Close()
        if !ok {
            artifactError(w, 503, "storage unavailable")
            return
        }
        artifactJSON(w, 200, map[string]interface{}{"status": "ok"})
        return
    }
    if !g.authorized(r) {
        artifactError(w, 401, "unauthorized")
        return
    }
    path, ok := g.pathFromRequest(r)
    if !ok || r.URL.RawQuery != "" {
        artifactError(w, 400, "invalid artifact identity")
        return
    }
    switch r.Method {
    case "PUT":
        g.put(w, r, path)
    case "GET", "HEAD":
        g.read(w, r, path)
    default:
        w.Header().Set("Allow", "GET, HEAD, PUT")
        artifactError(w, 405, "method not allowed")
    }
}

func (g *artifactGateway) put(w http.ResponseWriter, r *http.Request, path string) {
    declared := r.Header.Get("X-Content-SHA256")
    if !validDigest(declared) || r.ContentLength <= 0 || r.ContentLength > g.maxBytes {
        artifactError(w, 400, "Content-Length and lowercase X-Content-SHA256 required within size limit")
        return
    }
    // Stage on private local disk before writing anything to Dufs. A bad checksum
    // or interrupted sender cannot publish a truncated or wrong remote artifact.
    stage, err := os.CreateTemp(g.stagingDir, "ci-artifact-*.tmp")
    if err != nil {
        artifactError(w, 507, "staging unavailable")
        return
    }
    defer os.Remove(stage.Name())
    defer stage.Close()
    h := sha256.New()
    n, err := io.Copy(io.MultiWriter(stage, h), http.MaxBytesReader(w, r.Body, g.maxBytes))
    if err != nil || n != r.ContentLength || hex.EncodeToString(h.Sum(nil)) != declared {
        artifactError(w, 422, "incomplete upload or checksum mismatch")
        return
    }
    if err := stage.Sync(); err != nil {
        artifactError(w, 507, "staging sync failed")
        return
    }
    if _, err := stage.Seek(0, io.SeekStart); err != nil {
        artifactError(w, 500, "staging seek failed")
        return
    }

    mutex := g.slot(path)
    mutex.Lock()
    defer mutex.Unlock()
    ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
    defer cancel()

    existing, exists, err := g.remoteHash(ctx, path)
    if err != nil {
        artifactError(w, 502, "could not verify destination state")
        return
    }
    if exists {
        if existing != declared {
            artifactError(w, 409, "immutable artifact already exists with different content")
            return
        }
        artifactJSON(w, 200, map[string]interface{}{"status": "existing", "path": path, "sha256": declared, "size": n})
        return
    }
    if err := g.ensureDirs(ctx, path); err != nil {
        artifactError(w, 502, "could not create destination directories")
        return
    }
    random := make([]byte, 16)
    if _, err := rand.Read(random); err != nil {
        artifactError(w, 500, "random source unavailable")
        return
    }
    tmp := path + ".upload-" + hex.EncodeToString(random)
    defer g.deleteTemp(tmp)
    resp, err := g.do(ctx, "PUT", tmp, stage, n, map[string]string{"Content-Type": "application/octet-stream"})
    if err != nil {
        artifactError(w, 502, "storage upload failed")
        return
    }
    status := resp.StatusCode
    resp.Body.Close()
    if status < 200 || status >= 300 {
        artifactError(w, 502, fmt.Sprintf("storage upload failed: HTTP %d", status))
        return
    }
    remoteSum, ok, err := g.remoteHash(ctx, tmp)
    if err != nil || !ok || remoteSum != declared {
        artifactError(w, 502, "remote staging checksum mismatch")
        return
    }
    target := strings.TrimRight(g.dufs.BaseURL, "/") + "/" + path
    resp, err = g.do(ctx, "MOVE", tmp, nil, -1, map[string]string{"Destination": target, "Overwrite": "F"})
    if err != nil {
        artifactError(w, 502, "storage commit failed")
        return
    }
    status = resp.StatusCode
    resp.Body.Close()
    if status < 200 || status >= 300 {
        artifactError(w, 502, fmt.Sprintf("storage commit failed: HTTP %d", status))
        return
    }
    committed, ok, err := g.remoteHash(ctx, path)
    if err != nil || !ok || committed != declared {
        artifactError(w, 502, "remote committed checksum mismatch")
        return
    }
    artifactJSON(w, 201, map[string]interface{}{"status": "stored", "path": path, "sha256": declared, "size": n})
}

func (g *artifactGateway) read(w http.ResponseWriter, r *http.Request, path string) {
    ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
    defer cancel()
    digest, ok, err := g.remoteHash(ctx, path)
    if err != nil {
        artifactError(w, 502, "storage read failed")
        return
    }
    if !ok {
        artifactError(w, 404, "not found")
        return
    }
    resp, err := g.do(ctx, r.Method, path, nil, -1, nil)
    if err != nil {
        artifactError(w, 502, "storage read failed")
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        artifactError(w, 502, "storage download failed")
        return
    }
    w.Header().Set("X-Artifact-SHA256", digest)
    w.Header().Set("Content-Type", "application/octet-stream")
    w.Header().Set("Content-Disposition", "attachment")
    w.Header().Set("Cache-Control", "no-store")
    if resp.ContentLength >= 0 {
        w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
    }
    w.WriteHeader(200)
    if r.Method == "GET" {
        _, _ = io.Copy(w, resp.Body)
    }
}

func runArtifactMode(config Config) error {
    token := os.Getenv("CI_ARTIFACT_TOKEN")
    prefix := os.Getenv("CI_ARTIFACT_PREFIX")
    if prefix == "" {
        prefix = "ci-artifacts"
    }
    maxBytes := int64(1 << 30)
    if raw := os.Getenv("CI_ARTIFACT_MAX_BYTES"); raw != "" {
        n, err := strconv.ParseInt(raw, 10, 64)
        if err != nil {
            return err
        }
        maxBytes = n
    }
    gateway, err := newArtifactGateway(config, token, prefix, os.Getenv("CI_ARTIFACT_STAGING_DIR"), maxBytes)
    if err != nil {
        return err
    }
    bind := os.Getenv("CI_ARTIFACT_BIND")
    if bind == "" {
        bind = "127.0.0.1:7888"
    }
    listener, err := net.Listen("tcp", bind)
    if err != nil {
        return err
    }
    server := &http.Server{Handler: http.HandlerFunc(gateway.serveHTTP), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
    log.Printf("CI artifact gateway listening on %s (Dufs storage, authenticated)", listener.Addr())
    return server.Serve(listener)
}

var _ = filepath.Separator
