package gitlabx

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const refSnapshotPageSize int64 = 100

// RefState captures the GitLab metadata needed to compare a branch or tag.
type RefState struct {
	SHA               string    `json:"sha"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	HasRecentPipeline bool      `json:"has_recent_pipeline,omitempty"`
}

// RefSnapshot is a point-in-time inventory of project branches and tags.
type RefSnapshot struct {
	ObservedAt time.Time           `json:"observed_at"`
	Branches   map[string]RefState `json:"branches"`
	Tags       map[string]RefState `json:"tags"`
}

// GetRefSnapshot collects branch and tag targets and correlates recent pipeline
// refs without fetching or executing repository content.
func (c *Client) GetRefSnapshot(ctx context.Context, projectID any, recentSince time.Time) (RefSnapshot, error) {
	if c == nil || c.GL == nil {
		return RefSnapshot{}, fmt.Errorf("nil gitlab client")
	}
	if recentSince.IsZero() {
		recentSince = time.Now().UTC().Add(-15 * time.Minute)
	}
	snapshot := RefSnapshot{
		ObservedAt: time.Now().UTC(),
		Branches:   make(map[string]RefState),
		Tags:       make(map[string]RefState),
	}
	slog.Debug("collecting GitLab ref snapshot", "project", projectID)
	if err := c.collectBranches(ctx, projectID, snapshot.Branches); err != nil {
		return RefSnapshot{}, err
	}
	if err := c.collectTags(ctx, projectID, snapshot.Tags); err != nil {
		return RefSnapshot{}, err
	}
	if err := c.correlateRecentPipelines(ctx, projectID, recentSince, snapshot.Branches); err != nil {
		return RefSnapshot{}, err
	}
	slog.Debug("GitLab ref snapshot collected", "branches", len(snapshot.Branches), "tags", len(snapshot.Tags))
	return snapshot, nil
}

// IsCommitAncestor reports whether oldSHA is the merge base of oldSHA and
// newSHA, which means the branch movement is a fast-forward.
func (c *Client) IsCommitAncestor(ctx context.Context, projectID any, oldSHA, newSHA string) (bool, error) {
	if c == nil || c.GL == nil {
		return false, fmt.Errorf("nil gitlab client")
	}
	oldSHA = strings.TrimSpace(oldSHA)
	newSHA = strings.TrimSpace(newSHA)
	if oldSHA == "" || newSHA == "" {
		return false, fmt.Errorf("both commit SHAs are required")
	}
	refs := []string{oldSHA, newSHA}
	base, _, err := c.GL.Repositories.MergeBase(projectID, &gitlab.MergeBaseOptions{Ref: &refs}, gitlab.WithContext(ctx))
	if err != nil {
		return false, err
	}
	return base != nil && strings.EqualFold(strings.TrimSpace(base.ID), oldSHA), nil
}

func (c *Client) collectBranches(ctx context.Context, projectID any, out map[string]RefState) error {
	options := &gitlab.ListBranchesOptions{ListOptions: gitlab.ListOptions{PerPage: refSnapshotPageSize, Page: 1}}
	for {
		branches, response, err := c.GL.Branches.ListBranches(projectID, options, gitlab.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("list branches: %w", err)
		}
		for _, branch := range branches {
			if branch == nil || branch.Commit == nil || strings.TrimSpace(branch.Name) == "" {
				continue
			}
			out[branch.Name] = RefState{SHA: branch.Commit.ID}
		}
		if paginationDone(response, len(branches)) {
			return nil
		}
		options.Page = response.NextPage
	}
}

func (c *Client) collectTags(ctx context.Context, projectID any, out map[string]RefState) error {
	options := &gitlab.ListTagsOptions{ListOptions: gitlab.ListOptions{PerPage: refSnapshotPageSize, Page: 1}}
	for {
		tags, response, err := c.GL.Tags.ListTags(projectID, options, gitlab.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("list tags: %w", err)
		}
		for _, tag := range tags {
			if tag == nil || strings.TrimSpace(tag.Name) == "" {
				continue
			}
			sha := strings.TrimSpace(tag.Target)
			if tag.Commit != nil && strings.TrimSpace(tag.Commit.ID) != "" {
				sha = tag.Commit.ID
			}
			createdAt := time.Time{}
			if tag.CreatedAt != nil {
				createdAt = *tag.CreatedAt
			}
			out[tag.Name] = RefState{SHA: sha, CreatedAt: createdAt}
		}
		if paginationDone(response, len(tags)) {
			return nil
		}
		options.Page = response.NextPage
	}
}

func (c *Client) correlateRecentPipelines(
	ctx context.Context,
	projectID any,
	recentSince time.Time,
	branches map[string]RefState,
) error {
	options := &gitlab.ListProjectPipelinesOptions{
		ListOptions:  gitlab.ListOptions{PerPage: refSnapshotPageSize, Page: 1},
		UpdatedAfter: &recentSince,
	}
	for {
		pipelines, response, err := c.GL.Pipelines.ListProjectPipelines(projectID, options, gitlab.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("list recent pipelines: %w", err)
		}
		for _, pipelineInfo := range pipelines {
			if pipelineInfo == nil {
				continue
			}
			state, exists := branches[pipelineInfo.Ref]
			if !exists {
				continue
			}
			state.HasRecentPipeline = true
			branches[pipelineInfo.Ref] = state
		}
		if paginationDone(response, len(pipelines)) {
			return nil
		}
		options.Page = response.NextPage
	}
}

func paginationDone(response *gitlab.Response, itemCount int) bool {
	return response == nil || response.NextPage == 0 || response.CurrentPage >= response.TotalPages || itemCount == 0
}
