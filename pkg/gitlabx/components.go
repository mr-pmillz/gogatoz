package gitlabx

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetComponentYAML fetches the YAML content of a GitLab CI/CD component using the GraphQL API.
// The id should be the component identifier (e.g., "group/component" or a fully qualified ID),
// and version is optional (empty selects the default per the server behavior).
//
// NOTE: GitLab's GraphQL schema for CI/CD components can vary by version. We keep the query minimal
// and then heuristically locate a string field named one of: content, yaml, ciYml, text within the
// returned data payload.
func (c *Client) GetComponentYAML(ctx context.Context, id, version string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("nil client")
	}
	if id == "" {
		return "", fmt.Errorf("component id is required")
	}
	q := `query($id: String!, $version: String){
	  gogatozComponent: ciComponent(id: $id, version: $version) { yaml content }
	}`
	vars := map[string]any{"id": id}
	if version != "" {
		vars["version"] = version
	}
	data, err := c.GraphQL(ctx, q, vars)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("decode component graphql: %w", err)
	}
	if y, ok := findYAMLString(m); ok {
		return y, nil
	}
	return "", fmt.Errorf("component yaml not found in graphql response")
}

// findYAMLString recursively searches for likely YAML content string in a JSON-like structure.
func findYAMLString(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			if k == "content" || k == "yaml" || k == "ciYml" || k == "text" {
				if s, ok := vv.(string); ok && s != "" {
					return s, true
				}
			}
			if s, ok := findYAMLString(vv); ok {
				return s, ok
			}
		}
	case []any:
		for _, it := range t {
			if s, ok := findYAMLString(it); ok {
				return s, true
			}
		}
	}
	return "", false
}
