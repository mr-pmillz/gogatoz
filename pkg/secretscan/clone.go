package secretscan

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// CloneDestPath returns the local directory path for a project based on its
// namespace. For example, "group/subgroup/project" becomes
// outputDir/group/subgroup/project.
func CloneDestPath(outputDir, pathWithNamespace string) string {
	return filepath.Join(outputDir, filepath.FromSlash(pathWithNamespace))
}

// CloneProject shallow-clones a GitLab repository into destPath.
// If token is non-empty, it is injected into the HTTPS URL for authentication.
// depth controls the clone depth; 0 means full history.
func CloneProject(ctx context.Context, httpURL, token, destPath string, depth int) error {
	cloneURL := httpURL
	if token != "" {
		u, err := injectTokenIntoURL(httpURL, token)
		if err != nil {
			return fmt.Errorf("inject token: %w", err)
		}
		cloneURL = u
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	args := []string{"clone", "--quiet"}
	if depth > 0 {
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	args = append(args, cloneURL, destPath)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Sanitize output to avoid leaking token
		sanitized := sanitizeOutput(string(out), token)
		return fmt.Errorf("git clone %s: %s: %w", sanitizePath(httpURL), sanitized, err)
	}
	return nil
}

// injectTokenIntoURL inserts oauth2:token credentials into an HTTPS URL.
// Example: https://gitlab.com/group/project.git →
//
//	https://oauth2:TOKEN@gitlab.com/group/project.git
func injectTokenIntoURL(rawURL, token string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	u.User = url.UserPassword("oauth2", token)
	return u.String(), nil
}

// DiscoverRepos walks a directory tree and returns paths to directories
// containing a .git subdirectory. This supports the --scan-dir flag.
func DiscoverRepos(root string) ([]string, error) {
	var repos []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible dirs
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == ".git" {
			repos = append(repos, filepath.Dir(path))
			return filepath.SkipDir
		}
		return nil
	})
	return repos, err
}

// sanitizeOutput removes tokens from error messages.
func sanitizeOutput(output, token string) string {
	if token == "" {
		return strings.TrimSpace(output)
	}
	return strings.TrimSpace(strings.ReplaceAll(output, token, "***"))
}

// sanitizePath extracts just the path portion from a URL for safe logging.
func sanitizePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<url>"
	}
	return u.Path
}
