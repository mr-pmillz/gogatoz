package secretsdump

import (
	"context"
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Variable represents a minimal view of a GitLab variable returned by API.
// Value may be empty when masked or insufficient permissions.
type Variable struct {
	Scope     string `json:"scope,omitempty"`
	Key       string `json:"key"`
	Value     string `json:"value,omitempty"`
	Masked    bool   `json:"masked"`
	Protected bool   `json:"protected"`
}

// ListProjectVariables fetches project variables. If includeProtected is false, filters out protected ones.
func ListProjectVariables(ctx context.Context, client *gitlabx.Client, projectID any, includeProtected bool) ([]Variable, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	vars, _, err := client.GL.ProjectVariables.ListVariables(projectID, &gitlab.ListProjectVariablesOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]Variable, 0, len(vars))
	for _, v := range vars {
		if v == nil {
			continue
		}
		if !includeProtected && v.Protected {
			continue
		}
		mv := Variable{Key: v.Key}
		mv.Scope = v.EnvironmentScope
		mv.Masked = v.Masked
		mv.Protected = v.Protected
		mv.Value = v.Value
		out = append(out, mv)
	}
	return out, nil
}

// ListGroupVariables fetches group variables. If includeProtected is false, filters out protected ones.
func ListGroupVariables(ctx context.Context, client *gitlabx.Client, groupID any, includeProtected bool) ([]Variable, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	vars, _, err := client.GL.GroupVariables.ListVariables(groupID, &gitlab.ListGroupVariablesOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]Variable, 0, len(vars))
	for _, v := range vars {
		if v == nil {
			continue
		}
		if !includeProtected && v.Protected {
			continue
		}
		mv := Variable{Key: v.Key}
		mv.Scope = v.EnvironmentScope
		mv.Masked = v.Masked
		mv.Protected = v.Protected
		mv.Value = v.Value
		out = append(out, mv)
	}
	return out, nil
}
