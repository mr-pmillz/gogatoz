package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Test that ResolveIncludesWithOptions records provenance for jobs merged from includes.
func TestResolveIncludes_Provenance_Remote(t *testing.T) {
	// Fake remote include server returning a simple CI YAML with one job.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("stages: [test]\n\njob_from_remote:\n  script: ['echo hi']\n"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	// Base document that includes the remote YAML.
	baseYAML := "include:\n  - remote: " + srv.URL + "\n"
	base, err := Parse(strings.NewReader(baseYAML))
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	ctx := context.Background()
	merged, err := ResolveIncludesWithOptions(ctx, nil, nil, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
	})
	if err != nil {
		// Partial errors are acceptable, but should not happen here
		t.Fatalf("resolve includes: %v", err)
	}
	// Expect the job from the remote include to be present
	found := false
	for _, j := range merged.Jobs {
		if j.Name == "job_from_remote" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected job_from_remote to be merged; jobs=%+v", merged.Jobs)
	}
	// Verify provenance recorded for the job
	incs := merged.Provenance["job_from_remote"]
	if len(incs) != 1 {
		t.Fatalf("expected 1 provenance entry, got %d: %+v", len(incs), incs)
	}
	if incs[0].Type != IncludeRemote || strings.TrimSpace(incs[0].Remote) != srv.URL {
		t.Fatalf("unexpected provenance entry: %+v", incs[0])
	}
}
