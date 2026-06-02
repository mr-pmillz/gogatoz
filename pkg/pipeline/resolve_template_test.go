package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestTemplateIncludeResolution(t *testing.T) {
	// Mock GitLab API endpoint for CI templates
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v4/templates/gitlab_ci_yml/") {
			resp := map[string]any{
				"name":    "Example",
				"content": "stages: [build]\njob1:\n  script: ['echo from template']\n",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	_ = u

	// Build client pointing to our test server
	cl, err := gitlabx.New(ts.URL, "")
	if err != nil {
		t.Fatalf("client new: %v", err)
	}

	base := &Document{Includes: []Include{{Type: IncludeTemplate, Template: "Example"}}}
	ctx := context.Background()
	merged, err := ResolveIncludesWithOptions(ctx, cl, 0, "", base, 2, ResolveOptions{})
	if err != nil {
		// Template resolution should succeed without partial errors
		// Depending on implementation, partial errors would include unrelated messages, so fail here
		t.Fatalf("unexpected error: %v", err)
	}
	if merged == nil {
		t.Fatalf("expected merged document, got nil")
	}
	if len(merged.Jobs) != 1 {
		t.Fatalf("expected 1 job from template include, got %d", len(merged.Jobs))
	}
	if len(merged.Stages) != 1 || merged.Stages[0] != stageBuild {
		t.Fatalf("expected stages ['build'], got %v", merged.Stages)
	}
}
