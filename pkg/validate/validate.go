package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// Capability represents the result of probing a single API endpoint.
type Capability struct {
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint"`
	Accessible bool   `json:"accessible"`
	Detail     string `json:"detail,omitempty"`
}

// TokenProfile holds the full result of token validation and scope probing.
type TokenProfile struct {
	TokenName    string       `json:"token_name,omitempty"`
	Scopes       []string     `json:"scopes,omitempty"`
	ExpiresAt    string       `json:"expires_at,omitempty"`
	UserID       int64        `json:"user_id"`
	Username     string       `json:"username"`
	Name         string       `json:"name"`
	IsAdmin      bool         `json:"is_admin"`
	Capabilities []Capability `json:"capabilities"`
}

// ProbeToken validates a GitLab token and probes API endpoints to map its
// effective capabilities. This is the GitLab equivalent of gato-x's
// --validate / --probe-scopes mode.
func ProbeToken(ctx context.Context, client *gitlabx.Client) (*TokenProfile, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	p := &TokenProfile{}

	// 1. PAT self-introspection (GitLab 16.0+)
	probePATSelf(ctx, client, p)

	// 2. Current user identity
	if err := probeUser(ctx, client, p); err != nil {
		return nil, fmt.Errorf("probe user identity: %w", err)
	}

	// 3. Probe capability endpoints
	p.Capabilities = probeCapabilities(ctx, client)

	return p, nil
}

func probePATSelf(ctx context.Context, client *gitlabx.Client, p *TokenProfile) {
	body, status := apiGet(ctx, client, "/api/v4/personal_access_tokens/self")
	if status != http.StatusOK || body == nil {
		slog.Debug("PAT self-introspection unavailable", "status", status)
		return
	}
	var pat struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &pat); err == nil {
		p.TokenName = pat.Name
		p.Scopes = pat.Scopes
		p.ExpiresAt = pat.ExpiresAt
	}
}

func probeUser(ctx context.Context, client *gitlabx.Client, p *TokenProfile) error {
	body, status := apiGet(ctx, client, "/api/v4/user")
	if status != http.StatusOK || body == nil {
		return fmt.Errorf("cannot identify token owner (HTTP %d)", status)
	}
	var user struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return fmt.Errorf("parse user response: %w", err)
	}
	p.UserID = user.ID
	p.Username = user.Username
	p.Name = user.Name
	p.IsAdmin = user.IsAdmin
	return nil
}

type probeSpec struct {
	name     string
	endpoint string
	detail   func(body []byte) string
}

func probeCapabilities(ctx context.Context, client *gitlabx.Client) []Capability {
	specs := []probeSpec{
		{"List Projects (member)", "/api/v4/projects?membership=true&per_page=1", countDetail("projects")},
		{"List Groups", "/api/v4/groups?per_page=1", countDetail("groups")},
		{"List Users", "/api/v4/users?per_page=1", countDetail("users")},
		{"Admin Runners", "/api/v4/runners/all?per_page=1", countDetail("runners")},
		{"Admin Settings", "/api/v4/application/settings", nil},
	}
	caps := make([]Capability, 0, len(specs))
	for _, s := range specs {
		body, status := apiGet(ctx, client, s.endpoint)
		accessible := status == http.StatusOK
		detail := ""
		if accessible && s.detail != nil && body != nil {
			detail = s.detail(body)
		}
		caps = append(caps, Capability{
			Name:       s.name,
			Endpoint:   s.endpoint,
			Accessible: accessible,
			Detail:     detail,
		})
	}
	return caps
}

func countDetail(label string) func([]byte) string {
	return func(body []byte) string {
		var arr []json.RawMessage
		if json.Unmarshal(body, &arr) == nil {
			if len(arr) > 0 {
				return fmt.Sprintf("%s found", label)
			}
			return fmt.Sprintf("no %s", label)
		}
		return "accessible"
	}
}

func apiGet(ctx context.Context, client *gitlabx.Client, relPath string) ([]byte, int) {
	url := client.APIURL(relPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("PRIVATE-TOKEN", client.Token())
	resp, err := client.HTTPClient().Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode
}
