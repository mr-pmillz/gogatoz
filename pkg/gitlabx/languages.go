package gitlabx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GetProjectLanguages returns the language usage map for a project using
// GitLab REST API v4: GET /projects/:id/languages
// The returned map keys are language names and values are percentages.
func (c *Client) GetProjectLanguages(ctx context.Context, projectID int64) (map[string]float64, error) {
	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("nil client")
	}
	u := fmt.Sprintf("%s/api/v4/projects/%d/languages", c.baseURL, projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL constructed from client's own baseURL
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("get languages: http %d: %s", resp.StatusCode, string(b))
	}
	var m map[string]float64
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("decode languages: %w", err)
	}
	if m == nil {
		m = map[string]float64{}
	}
	return m, nil
}
