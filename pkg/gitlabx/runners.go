package gitlabx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// RunnerInfo is a minimal view of a GitLab Runner we care about for exposure analysis.
//
//nolint:tagliatelle // keep JSON keys idiomatic for output
type RunnerInfo struct {
	ID          int64    `json:"id"`
	Description string   `json:"description,omitempty"`
	Active      bool     `json:"active"`
	IsShared    bool     `json:"is_shared"`
	Online      bool     `json:"online"`
	Status      string   `json:"status,omitempty"`
	TagList     []string `json:"tag_list,omitempty"`
	Executor    string   `json:"executor,omitempty"`
}

// parseRunnerPage decodes a runners list HTTP response and returns the items and next page.
// It always closes the response body. label is used for contextual error messages.
func parseRunnerPage(resp *http.Response, label string) ([]RunnerInfo, int, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("%s: http %d", label, resp.StatusCode)
	}
	var raw []struct {
		ID          int64    `json:"id"`
		Description string   `json:"description"`
		Active      bool     `json:"active"`
		IsShared    bool     `json:"is_shared"`
		Online      bool     `json:"online"`
		Status      string   `json:"status"`
		TagList     []string `json:"tag_list"`
		Executor    string   `json:"executor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, 0, err
	}
	items := make([]RunnerInfo, 0, len(raw))
	for _, r := range raw {
		items = append(items, RunnerInfo{ID: r.ID, Description: r.Description, Active: r.Active, IsShared: r.IsShared, Online: r.Online, Status: r.Status, TagList: r.TagList, Executor: r.Executor})
	}
	next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
	if next == "" {
		return items, 0, nil
	}
	if n, err := strconv.Atoi(next); err == nil {
		return items, n, nil
	}
	return items, 0, nil
}

// ListProjectRunners lists runners available to the given project.
func (c *Client) ListProjectRunners(ctx context.Context, projectID any, perPage, page int64) ([]RunnerInfo, *gitlab.Response, error) {
	opt := &gitlab.ListProjectRunnersOptions{ListOptions: gitlab.ListOptions{PerPage: perPage, Page: page}}
	runs, resp, err := c.GL.Runners.ListProjectRunners(projectID, opt, gitlab.WithContext(ctx))
	if err != nil {
		return nil, resp, err
	}
	out := make([]RunnerInfo, 0, len(runs))
	for _, r := range runs {
		// Some fields (TagList, Executor) may not be exposed in this listing; we only copy what is available.
		out = append(out, RunnerInfo{
			ID:          r.ID,
			Description: r.Description,
			Active:      !r.Paused,
			IsShared:    r.IsShared,
			Online:      r.Online,
			Status:      r.Status,
		})
	}
	return out, resp, nil
}

// AccumulateProjectRunners pages through all project runners and returns a slice.
func (c *Client) AccumulateProjectRunners(ctx context.Context, projectID any) ([]RunnerInfo, error) {
	var all []RunnerInfo
	var page int64 = 1
	for {
		items, resp, err := c.ListProjectRunners(ctx, projectID, 100, page)
		if err != nil {
			// Best-effort; surface contextual error
			return all, fmt.Errorf("list project runners page %d: %w", page, err)
		}
		all = append(all, items...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return all, nil
}

// AccumulateGroupRunners lists runners for a group (admin/maintainer can see group runners).
// Uses raw HTTP to avoid SDK gaps.
func (c *Client) AccumulateGroupRunners(ctx context.Context, groupID any) ([]RunnerInfo, error) {
	var all []RunnerInfo
	gid := fmt.Sprintf("%v", groupID)
	gidEsc := url.PathEscape(gid)
	page := 1
	for {
		u := c.APIURL(fmt.Sprintf("/api/v4/groups/%s/runners?per_page=100&page=%d", gidEsc, page))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // G704: URL constructed from trusted API base + path-escaped group ID
		if err != nil {
			return all, err
		}
		if tok := c.Token(); tok != "" {
			req.Header.Set("PRIVATE-TOKEN", tok)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient.Do(req) //nolint:gosec
		if err != nil {
			return all, err
		}
		items, next, perr := parseRunnerPage(resp, "list group runners")
		if perr != nil {
			return all, perr
		}
		all = append(all, items...)
		page = next
		if page == 0 {
			break
		}
	}
	return all, nil
}

// AccumulateAllRunners lists all instance runners (admin only). Uses /runners/all.
func (c *Client) AccumulateAllRunners(ctx context.Context) ([]RunnerInfo, error) {
	var all []RunnerInfo
	page := 1
	for {
		u := c.APIURL(fmt.Sprintf("/api/v4/runners/all?per_page=100&page=%d", page))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return all, err
		}
		if tok := c.Token(); tok != "" {
			req.Header.Set("PRIVATE-TOKEN", tok)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient.Do(req) //nolint:gosec
		if err != nil {
			return all, err
		}
		items, next, perr := parseRunnerPage(resp, "list all runners")
		if perr != nil {
			return all, perr
		}
		all = append(all, items...)
		page = next
		if page == 0 {
			break
		}
	}
	return all, nil
}
