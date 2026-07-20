package gitlabx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

// accumulateRunners paginates through a runners API endpoint using raw HTTP.
func (c *Client) accumulateRunners(ctx context.Context, pathFmt string, label string) ([]RunnerInfo, error) {
	var all []RunnerInfo
	page := 1
	for {
		u := c.APIURL(fmt.Sprintf(pathFmt+"?per_page=100&page=%d", page))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // URL constructed from trusted API base
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
		items, next, perr := parseRunnerPage(resp, label)
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

// AccumulateProjectRunners pages through all project runners and returns a slice.
func (c *Client) AccumulateProjectRunners(ctx context.Context, projectID any) ([]RunnerInfo, error) {
	pid := url.PathEscape(fmt.Sprintf("%v", projectID))
	return c.accumulateRunners(ctx, "/api/v4/projects/"+pid+"/runners", "list project runners")
}

// AccumulateGroupRunners lists runners for a group (admin/maintainer can see group runners).
func (c *Client) AccumulateGroupRunners(ctx context.Context, groupID any) ([]RunnerInfo, error) {
	gid := url.PathEscape(fmt.Sprintf("%v", groupID))
	return c.accumulateRunners(ctx, "/api/v4/groups/"+gid+"/runners", "list group runners")
}

// AccumulateAllRunners lists all instance runners (admin only).
func (c *Client) AccumulateAllRunners(ctx context.Context) ([]RunnerInfo, error) {
	return c.accumulateRunners(ctx, "/api/v4/runners/all", "list all runners")
}
