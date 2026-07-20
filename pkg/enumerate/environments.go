package enumerate

import (
	"context"
	"log/slog"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// FetchEnvironments retrieves environment metadata for a project.
func FetchEnvironments(ctx context.Context, cl *gitlabx.Client, projectID any) ([]analyze.EnvironmentInfo, error) {
	slog.Debug("fetching environments", "project_id", projectID)
	var all []analyze.EnvironmentInfo
	page := int64(1)
	for {
		envs, resp, err := cl.GL.Environments.ListEnvironments(projectID,
			&gitlab.ListEnvironmentsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}},
			gitlab.WithContext(ctx))
		if err != nil {
			return all, err
		}
		for _, e := range envs {
			info := analyze.EnvironmentInfo{
				ID:    e.ID,
				Name:  e.Name,
				State: e.State,
			}
			if e.Tier != "" {
				info.Tier = e.Tier
			}
			if e.ExternalURL != "" {
				info.ExternalURL = e.ExternalURL
			}
			if e.LastDeployment != nil && e.LastDeployment.CreatedAt != nil {
				t := *e.LastDeployment.CreatedAt
				info.LastDeployedAt = &t
			}
			all = append(all, info)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	slog.Debug("fetched environments", "project_id", projectID, "count", len(all))
	return all, nil
}
