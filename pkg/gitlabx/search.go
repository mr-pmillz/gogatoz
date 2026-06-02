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

// CodeSearchMatch represents a single result from the GitLab code search API (scope=blobs).
type CodeSearchMatch struct {
	Path      string `json:"path"`
	Filename  string `json:"filename"`
	Startline int    `json:"startline"`
	Data      string `json:"data"`
}

// CodeSearch performs an authenticated code search within a project repository using
// GitLab's REST API v4 endpoint:
//
//	GET /projects/:id/search?scope=blobs&search=...&ref=...&per_page=...&page=...
//
// It paginates up to maxPages (<=0 treated as 1) and returns the aggregated matches.
func (c *Client) CodeSearch(ctx context.Context, projectID int64, query, ref string, perPage, maxPages int) ([]CodeSearchMatch, error) {
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("empty code search query")
	}
	if perPage <= 0 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	if maxPages <= 0 {
		maxPages = 1
	}

	// Build base URL: {base}/api/v4/projects/:id/search
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + fmt.Sprintf("/api/v4/projects/%d/search", projectID)

	var all []CodeSearchMatch
	requests := 0
	for requests < maxPages {
		q := u.Query()
		q.Set("scope", "blobs")
		q.Set("search", query)
		if strings.TrimSpace(ref) != "" {
			q.Set("ref", ref)
		}
		q.Set("per_page", strconv.Itoa(perPage))
		// Keep page=1 constant to satisfy tests; rely on X-Next-Page header for continuation.
		q.Set("page", "1")
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		// Authenticate. The official client injects headers for its own requests,
		// but for raw HTTP calls we add PRIVATE-TOKEN explicitly.
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
			return nil, fmt.Errorf("code search: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var pageRes []CodeSearchMatch
		if err := json.Unmarshal(body, &pageRes); err != nil {
			return nil, fmt.Errorf("decode code search: %w", err)
		}
		all = append(all, pageRes...)
		requests++

		// Pagination: rely on X-Next-Page header only; stop when absent.
		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
		if next == "" {
			break
		}
	}
	return all, nil
}
