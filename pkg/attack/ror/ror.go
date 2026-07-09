package ror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// RunnerSummary holds minimal details discovered for runners attached to a project.
// It focuses on tags and type needed for Runner-on-Runner targeting.
type RunnerSummary struct {
	ID          int64    `json:"id"`
	Description string   `json:"description"`
	IsShared    bool     `json:"is_shared"`
	RunnerType  string   `json:"runner_type"`
	Tags        []string `json:"tag_list"`
}

// DiscoverProjectRunnerTags lists runners accessible to the given project and returns the unique tag set.
// Requires token scopes permitting access to project runners. It does not require admin permissions.
func DiscoverProjectRunnerTags(ctx context.Context, client *gitlabx.Client, projectID any) ([]string, []RunnerSummary, error) {
	if client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}
	id := fmt.Sprintf("%v", projectID)
	// Support path-with-namespace by URL-encoding it for the REST path segment.
	idEsc := url.PathEscape(id)
	rel := fmt.Sprintf("/api/v4/projects/%s/runners?per_page=100", idEsc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.APIURL(rel), nil)
	if err != nil {
		return nil, nil, err
	}
	if tok := client.Token(); tok != "" {
		req.Header.Set("PRIVATE-TOKEN", tok)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.HTTPClient().Do(req) //nolint:gosec // G704: URL constructed from client's own baseURL
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("list project runners: http %d", resp.StatusCode)
	}
	var runners []RunnerSummary
	if err := json.NewDecoder(resp.Body).Decode(&runners); err != nil {
		return nil, nil, err
	}
	// Build unique tags
	set := map[string]struct{}{}
	for _, r := range runners {
		for _, t := range r.Tags {
			ts := strings.TrimSpace(t)
			if ts == "" {
				continue
			}
			set[ts] = struct{}{}
		}
	}
	tags := make([]string, 0, len(set))
	for k := range set {
		tags = append(tags, k)
	}
	return tags, runners, nil
}

// SharedRunnerInfo describes a runner shared across multiple projects in a group.
type SharedRunnerInfo struct {
	RunnerID    int64    `json:"runner_id"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	ProjectIDs  []int64  `json:"project_ids"`
	Paused      bool     `json:"paused"`
}

// DiscoverGroupRunnerSharing enumerates runners shared across a GitLab group,
// identifying runners accessible from multiple projects (lateral movement surface).
func DiscoverGroupRunnerSharing(ctx context.Context, client *gitlabx.Client, groupID any) ([]SharedRunnerInfo, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}

	// List all runners available to the group.
	var allRunners []*gitlab.Runner
	opts := &gitlab.ListGroupsRunnersOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
	}
	for {
		runners, resp, err := client.GL.Runners.ListGroupsRunners(groupID, opts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("list group runners: %w", err)
		}
		allRunners = append(allRunners, runners...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	var shared []SharedRunnerInfo
	for _, r := range allRunners {
		// Get runner details to retrieve tags.
		details, _, err := client.GL.Runners.GetRunnerDetails(r.ID, gitlab.WithContext(ctx))
		if err != nil {
			// Skip runners we cannot inspect (permission issues).
			continue
		}

		// Discover project IDs from recent jobs processed by this runner.
		projectSet := map[int64]struct{}{}
		jobOpts := &gitlab.ListRunnerJobsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		}
		for {
			jobs, resp, err := client.GL.Runners.ListRunnerJobs(r.ID, jobOpts, gitlab.WithContext(ctx))
			if err != nil {
				break
			}
			for _, j := range jobs {
				if j.Project != nil && j.Project.ID != 0 {
					projectSet[j.Project.ID] = struct{}{}
				}
			}
			if resp.NextPage == 0 {
				break
			}
			jobOpts.Page = resp.NextPage
		}

		// Only include runners that serve multiple projects (lateral movement surface).
		if len(projectSet) < 2 {
			continue
		}

		ids := make([]int64, 0, len(projectSet))
		for id := range projectSet {
			ids = append(ids, id)
		}
		slices.Sort(ids)

		tags := make([]string, len(details.TagList))
		copy(tags, details.TagList)

		shared = append(shared, SharedRunnerInfo{
			RunnerID:    r.ID,
			Description: r.Description,
			Tags:        tags,
			ProjectIDs:  ids,
			Paused:      r.Paused,
		})
	}

	return shared, nil
}

// FilterTagsByExecutor returns tags that loosely match an executor string (docker|shell|kubernetes).
// This is a heuristic based on tag names used by admins; the GitLab project-runners endpoint
// does not expose executor details to non-admin callers.
func FilterTagsByExecutor(tags []string, executor string) []string {
	ex := strings.ToLower(strings.TrimSpace(executor))
	if ex == "" {
		return tags
	}
	var out []string
	for _, t := range tags {
		lt := strings.ToLower(t)
		if strings.Contains(lt, ex) || (ex == "docker" && (strings.Contains(lt, "dind") || strings.Contains(lt, "container"))) {
			out = append(out, t)
		}
	}
	return out
}
