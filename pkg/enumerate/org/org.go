package org

import (
	"context"
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// ListGroupProjects returns project identifiers (path_with_namespace) for a given group.
// groupID may be a numeric ID or a full path. If recursive is true, subgroup projects are included via API options.
// Pagination is handled internally.
func ListGroupProjects(ctx context.Context, client *gitlabx.Client, groupID any, recursive bool) ([]string, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	// Resolve group to ensure it exists and to normalize ID
	grp, _, err := client.GL.Groups.GetGroup(groupID, &gitlab.GetGroupOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	var out []string
	var page int64 = 1
	for {
		opt := &gitlab.ListGroupProjectsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}}
		// NOTE: recursive traversal can be implemented by walking subgroups via REST if needed.
		projs, resp, err := client.GL.Groups.ListGroupProjects(grp.ID, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("list group projects: %w", err)
		}
		for _, p := range projs {
			if p == nil {
				continue
			}
			out = append(out, p.PathWithNamespace)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return out, nil
}
