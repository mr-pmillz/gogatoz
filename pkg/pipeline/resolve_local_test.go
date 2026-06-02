package pipeline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

const includedJobYAML = `stages: [deploy]
deploy_job:
  stage: deploy
  script: ["echo deploying"]
  tags: ["prod"]
`

// TestResolveIncludes_LocalInclude verifies that a local include is fetched via the
// GitLab repository files API and merged into the base document.
func TestResolveIncludes_LocalInclude(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(includedJobYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET /api/v4/projects/:id/repository/files/:path
		if strings.Contains(r.URL.Path, "/repository/files/") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": "deploy.yml",
				"file_path": "deploy.yml",
				"encoding":  "base64",
				"content":   encoded,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	base := &Document{
		Stages: []string{"build"},
		Includes: []Include{
			{Type: IncludeLocal, Local: "deploy.yml"},
		},
		Jobs: []Job{
			{Name: "build_job", Stage: "build", Script: []string{"make build"}},
		},
	}

	ctx := context.Background()
	merged, err := ResolveIncludes(ctx, cl, "1", "main", base, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify included job appears
	_, ok := findJob(merged, "deploy_job")
	if !ok {
		t.Fatalf("expected deploy_job from local include, jobs=%+v", merged.Jobs)
	}
	// Verify stages merged (unique)
	found := false
	for _, s := range merged.Stages {
		if s == "deploy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'deploy' stage merged, got %v", merged.Stages)
	}
	// Original job should still exist
	_, ok = findJob(merged, "build_job")
	if !ok {
		t.Fatal("expected original build_job to remain after merge")
	}
}

// TestResolveIncludes_ProjectInclude_PinnedVsUnpinned tests that a pinned project
// include (with ref) resolves without partial errors, while an unpinned one gets an
// "unpinned" partial error.
func TestResolveIncludes_ProjectInclude_PinnedVsUnpinned(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(includedJobYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Handle GetProject
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  10,
				"default_branch":      "main",
				"path_with_namespace": "other/project",
			})
			return
		}
		// Handle repository file fetch
		if strings.Contains(r.URL.Path, "/repository/files/") {
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": "ci.yml",
				"file_path": "ci.yml",
				"encoding":  "base64",
				"content":   encoded,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	t.Run("pinned", func(t *testing.T) {
		base := &Document{
			Includes: []Include{
				{Type: IncludeProject, Project: "other/project", File: []string{"ci.yml"}, Ref: "v1.0"},
			},
		}
		merged, err := ResolveIncludes(context.Background(), cl, "1", "main", base, 2)
		if err != nil {
			t.Fatalf("expected no error for pinned include, got: %v", err)
		}
		_, ok := findJob(merged, "deploy_job")
		if !ok {
			t.Fatalf("expected deploy_job from project include")
		}
	})

	t.Run("unpinned", func(t *testing.T) {
		base := &Document{
			Includes: []Include{
				{Type: IncludeProject, Project: "other/project", File: []string{"ci.yml"}}, // no Ref
			},
		}
		merged, err := ResolveIncludes(context.Background(), cl, "1", "main", base, 2)
		// Should have partial error about unpinned
		if err == nil {
			t.Fatal("expected partial error for unpinned project include")
		}
		if !strings.Contains(err.Error(), "unpinned") {
			t.Fatalf("expected 'unpinned' in error, got: %v", err)
		}
		// Job should still be merged despite partial error
		_, ok := findJob(merged, "deploy_job")
		if !ok {
			t.Fatal("expected deploy_job to be merged despite partial error")
		}
	})
}

// TestResolveIncludes_VisitedDedup verifies that the same include listed twice in a
// document is fetched only once (visited set deduplication).
func TestResolveIncludes_VisitedDedup(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(includedJobYAML))
	var fetchCount int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repository/files/") {
			atomic.AddInt64(&fetchCount, 1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": "shared.yml",
				"file_path": "shared.yml",
				"encoding":  "base64",
				"content":   encoded,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	base := &Document{
		Includes: []Include{
			{Type: IncludeLocal, Local: "shared.yml"},
			{Type: IncludeLocal, Local: "shared.yml"}, // duplicate
		},
	}

	ctx := context.Background()
	_, err = ResolveIncludes(ctx, cl, "1", "main", base, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := atomic.LoadInt64(&fetchCount)
	if count != 1 {
		t.Fatalf("expected exactly 1 fetch for deduped include, got %d", count)
	}
}

// TestResolveIncludes_NilDocument verifies that passing a nil base document returns an error.
func TestResolveIncludes_NilDocument(t *testing.T) {
	_, err := ResolveIncludes(context.Background(), nil, nil, "", nil, 2)
	if err == nil {
		t.Fatal("expected error for nil document")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected 'nil' in error, got: %v", err)
	}
}

// TestResolveIncludes_DepthZero verifies that depth=0 returns the base document unchanged.
func TestResolveIncludes_DepthZero(t *testing.T) {
	base := &Document{
		Includes: []Include{
			{Type: IncludeLocal, Local: "something.yml"},
		},
		Jobs: []Job{{Name: "original"}},
	}
	merged, err := ResolveIncludes(context.Background(), nil, nil, "", base, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(merged.Jobs) != 1 || merged.Jobs[0].Name != "original" {
		t.Fatalf("expected original job unchanged at depth 0, got %+v", merged.Jobs)
	}
}
