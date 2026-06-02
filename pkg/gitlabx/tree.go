package gitlabx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// RepoTreeEntry represents a single entry from the repository tree API.
// See: GET /projects/:id/repository/tree
// We only care about path and type; type is one of "tree" (directory) or "blob" (file).
type RepoTreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// ListRepoTreePaths lists file paths (type=blob) from a project's repository tree.
// It supports pagination and optional recursion. Returns only file paths.
//
//	GET {base}/api/v4/projects/:id/repository/tree?ref=...&recursive=true&per_page=...&page=...
//
// The logic mirrors GitLab pagination semantics and keeps branching local for
// performance; refactoring into smaller helpers would add allocations on hot
// paths during large scans. Kept as a single function for speed.
//
//nolint:gocognit
func (c *Client) ListRepoTreePaths(ctx context.Context, projectID int64, ref string, recursive bool, perPage, maxPages int) ([]string, error) {
	if perPage <= 0 {
		perPage = 100
	}
	if perPage > 100 {
		perPage = 100
	}
	if maxPages <= 0 {
		maxPages = 1
	}

	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + fmt.Sprintf("/api/v4/projects/%d/repository/tree", projectID)

	var all []string
	page := 1
	requests := 0
	for requests < maxPages {
		q := u.Query()
		if strings.TrimSpace(ref) != "" {
			q.Set("ref", ref)
		}
		if recursive {
			q.Set("recursive", "true")
		}
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req) //nolint:gosec
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("repo tree: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var entries []RepoTreeEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			return nil, fmt.Errorf("decode repo tree: %w", err)
		}
		for _, e := range entries {
			if e.Type == "blob" && strings.TrimSpace(e.Path) != "" {
				all = append(all, e.Path)
			}
		}
		requests++

		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
		if next == "" {
			break
		}
		nextInt, err := strconv.Atoi(next)
		if err != nil || nextInt == 0 {
			break
		}
		page = nextInt
	}
	return all, nil
}
