package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

// The MCP adapter has considerably broader powers than the CI gateway.
// Keep each destructive capability off until the operator explicitly enables it.
func enabled(key string) bool { return os.Getenv(key) == "true" }

func (s *MCPServer) remoteRoot() string {
    root := os.Getenv("DUFS_REMOTE_ROOT")
    if root == "" {
        root = s.config.UploadDir
    }
    root = strings.Trim(root, "/")
    if root == "" {
        root = "uploads"
    }
    return root
}

func (s *MCPServer) validateRemote(p string) error {
    if p == "" || strings.ContainsAny(p, "\\?#%") {
        return fmt.Errorf("invalid remote path")
    }
    p = strings.TrimPrefix(p, "/")
    for _, part := range strings.Split(p, "/") {
        if part == "" || part == "." || part == ".." {
            return fmt.Errorf("unsafe remote path")
        }
    }
    root := s.remoteRoot()
    if root != "." && root != "/" && p != root && !strings.HasPrefix(p, root+"/") {
        return fmt.Errorf("remote path outside DUFS_REMOTE_ROOT")
    }
    return nil
}

func validateLocal(p string, writing bool) error {
    root := os.Getenv("DUFS_LOCAL_ROOT")
    if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
        return fmt.Errorf("DUFS_LOCAL_ROOT must be an absolute, dedicated directory")
    }
    realRoot, err := filepath.EvalSymlinks(root)
    if err != nil {
        return fmt.Errorf("unavailable local root: %w", err)
    }
    abs, err := filepath.Abs(p)
    if err != nil {
        return err
    }
    // For new files validate the existing parent; for reads resolve all links.
    target := abs
    if writing {
        target = filepath.Dir(abs)
    }
    target, err = filepath.EvalSymlinks(target)
    if err != nil {
        return fmt.Errorf("invalid local path: %w", err)
    }
    rel, err := filepath.Rel(realRoot, target)
    if err != nil || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
        return fmt.Errorf("local path outside DUFS_LOCAL_ROOT")
    }
    if writing {
        if _, err := os.Lstat(abs); err == nil {
            return fmt.Errorf("refusing to overwrite a local file")
        } else if !os.IsNotExist(err) {
            return err
        }
    } else {
        info, err := os.Stat(abs)
        if err != nil {
            return err
        }
        if !info.Mode().IsRegular() {
            return fmt.Errorf("local upload source must be a regular file")
        }
    }
    return nil
}

func (s *MCPServer) authorizeTool(name string, args map[string]interface{}) error {
    checkPath := func(key string) error {
        value, ok := args[key].(string)
        if !ok || value == "" {
            return fmt.Errorf("%s is required", key)
        }
        return s.validateRemote(value)
    }
    checkLocal := func(key string, writing bool) error {
        value, ok := args[key].(string)
        if !ok || value == "" {
            return fmt.Errorf("explicit %s is required", key)
        }
        return validateLocal(value, writing)
    }
    switch name {
    case "dufs_health", "dufs_upload_status":
        return nil
    case "dufs_list":
        p, _ := args["path"].(string)
        if p == "" || p == "/" {
            p = "/" + s.remoteRoot()
            args["path"] = p
        }
        return s.validateRemote(p)
    case "dufs_get_hash":
        return checkPath("path")
    case "dufs_upload":
        if !enabled("DUFS_MCP_ENABLE_UPLOAD") {
            return fmt.Errorf("upload capability disabled")
        }
        if err := checkLocal("local_path", false); err != nil {
            return err
        }
        if p, _ := args["remote_path"].(string); p != "" {
            return s.validateRemote(p)
        }
        return s.validateRemote(s.resolveRemotePath(args["local_path"].(string), ""))
    case "dufs_upload_batch":
        if !enabled("DUFS_MCP_ENABLE_UPLOAD") {
            return fmt.Errorf("upload capability disabled")
        }
        files, ok := args["files"].([]interface{})
        if !ok || len(files) == 0 || len(files) > 32 {
            return fmt.Errorf("upload batch must contain 1 to 32 files")
        }
        for _, item := range files {
            f, ok := item.(map[string]interface{})
            if !ok {
                return fmt.Errorf("invalid upload entry")
            }
            if err := s.authorizeTool("dufs_upload", f); err != nil {
                return err
            }
        }
        return nil
    case "dufs_download", "dufs_download_folder":
        if !enabled("DUFS_MCP_ENABLE_DOWNLOAD") {
            return fmt.Errorf("local write capability disabled")
        }
        if err := checkPath("remote_path"); err != nil {
            return err
        }
        return checkLocal("local_path", true)
    case "dufs_create_dir":
        if !enabled("DUFS_MCP_ENABLE_MKDIR") {
            return fmt.Errorf("mkdir capability disabled")
        }
        return checkPath("path")
    case "dufs_delete":
        if !enabled("DUFS_MCP_ENABLE_DELETE") {
            return fmt.Errorf("delete capability disabled")
        }
        return checkPath("path")
    case "dufs_move":
        if !enabled("DUFS_MCP_ENABLE_MOVE") {
            return fmt.Errorf("move capability disabled")
        }
        if err := checkPath("source"); err != nil {
            return err
        }
        return checkPath("destination")
    default:
        return fmt.Errorf("unknown tool: %s", name)
    }
}
