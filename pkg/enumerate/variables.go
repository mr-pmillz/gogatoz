package enumerate

import (
	"context"
	"log/slog"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// FetchProjectVariables retrieves CI/CD variable metadata for a project.
// Only metadata (key, protected, masked, environment_scope) is returned;
// variable values are never fetched.
//
//nolint:dupl // ProjectVariable and GroupVariable are distinct SDK types; pagination structure is intentionally parallel
func FetchProjectVariables(ctx context.Context, cl *gitlabx.Client, projectID any) ([]analyze.VariableInfo, error) {
	slog.Debug("fetching project variables", "project_id", projectID)
	var all []analyze.VariableInfo
	page := int64(1)
	for {
		vars, resp, err := cl.GL.ProjectVariables.ListVariables(projectID,
			&gitlab.ListProjectVariablesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}},
			gitlab.WithContext(ctx))
		if err != nil {
			return all, err
		}
		for _, v := range vars {
			all = append(all, analyze.VariableInfo{
				Key:              v.Key,
				Protected:        v.Protected,
				Masked:           v.Masked,
				EnvironmentScope: v.EnvironmentScope,
				Source:           "project",
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	slog.Debug("fetched project variables", "project_id", projectID, "count", len(all))
	return all, nil
}

// FetchGroupVariables retrieves CI/CD variable metadata for a group.
// Only metadata (key, protected, masked, environment_scope) is returned;
// variable values are never fetched.
//
//nolint:dupl // ProjectVariable and GroupVariable are distinct SDK types; pagination structure is intentionally parallel
func FetchGroupVariables(ctx context.Context, cl *gitlabx.Client, groupID any) ([]analyze.VariableInfo, error) {
	slog.Debug("fetching group variables", "group_id", groupID)
	var all []analyze.VariableInfo
	page := int64(1)
	for {
		vars, resp, err := cl.GL.GroupVariables.ListVariables(groupID,
			&gitlab.ListGroupVariablesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}},
			gitlab.WithContext(ctx))
		if err != nil {
			return all, err
		}
		for _, v := range vars {
			all = append(all, analyze.VariableInfo{
				Key:              v.Key,
				Protected:        v.Protected,
				Masked:           v.Masked,
				EnvironmentScope: v.EnvironmentScope,
				Source:           "group",
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	slog.Debug("fetched group variables", "group_id", groupID, "count", len(all))
	return all, nil
}
