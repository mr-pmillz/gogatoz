package pivot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

// mockGitLab simulates GitLab API endpoints for orchestrator tests.
type mockGitLab struct {
	mu       sync.Mutex
	projects map[string]mockProject
	// Track branch/file operations
	branches map[string]bool   // "projectID/branch" -> exists
	files    map[string]string // "projectID/branch/path" -> content
}

type mockProject struct {
	ID                int64
	PathWithNamespace string
	DefaultBranch     string
	CIContent         string
	Runners           []mockRunner
	Variables         []mockVariable
}

type mockRunner struct {
	ID       int64
	TagList  []string
	Executor string
	Online   bool
}

type mockVariable struct {
	Key   string
	Value string
}

func newMockGitLab() *mockGitLab {
	return &mockGitLab{
		projects: make(map[string]mockProject),
		branches: make(map[string]bool),
		files:    make(map[string]string),
	}
}

//nolint:gocognit
func (m *mockGitLab) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		// Pagination headers (single page)
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "20")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "1")

		switch {
		case path == "/api/v4/user":
			json.NewEncoder(w).Encode(map[string]any{
				"id":       1,
				"username": "pivot-bot",
				"name":     "Pivot Bot",
			})

		case strings.Contains(path, "/repository/files/"):
			// File operations (create/update)
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"file_path": ".gitlab-ci.yml"})
				return
			}
			// File read (GET) - check if CI file
			if strings.Contains(path, ".gitlab-ci.yml") {
				// Return CI content for the project
				for _, p := range m.projects {
					if strings.Contains(path, fmt.Sprintf("/projects/%d/", p.ID)) || strings.Contains(path, fmt.Sprintf("/projects/%s/", strings.ReplaceAll(p.PathWithNamespace, "/", "%2F"))) {
						if p.CIContent != "" {
							json.NewEncoder(w).Encode(map[string]string{
								"content": p.CIContent,
							})
							return
						}
					}
				}
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNotFound)

		case strings.Contains(path, "/repository/branches"):
			if r.Method == http.MethodGet {
				// Branch exists check
				json.NewEncoder(w).Encode(map[string]any{
					"name":    "main",
					"default": true,
				})
				return
			}
			if r.Method == http.MethodPost {
				// Create branch
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]any{"name": "gogatoz-pivot"})
				return
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}

		case strings.HasSuffix(path, "/pipelines"):
			// List pipelines
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1001, "status": "success", "ref": "gogatoz-pivot"},
			})

		case strings.Contains(path, "/runners"):
			// Project runners
			var runners []map[string]any
			for _, p := range m.projects {
				if strings.Contains(path, fmt.Sprintf("/projects/%d/", p.ID)) {
					for _, rn := range p.Runners {
						runners = append(runners, map[string]any{
							"id":          rn.ID,
							"description": "runner",
							"tag_list":    rn.TagList,
							"online":      rn.Online,
							"paused":      false,
							"is_shared":   false,
						})
					}
				}
			}
			json.NewEncoder(w).Encode(runners)

		case strings.Contains(path, "/protected_branches"):
			json.NewEncoder(w).Encode([]map[string]any{})

		case strings.Contains(path, "/projects/"):
			// Get project
			for _, p := range m.projects {
				idStr := fmt.Sprintf("%d", p.ID)
				encoded := strings.ReplaceAll(p.PathWithNamespace, "/", "%2F")
				if strings.Contains(path, "/projects/"+idStr) || strings.Contains(path, "/projects/"+encoded) {
					json.NewEncoder(w).Encode(map[string]any{
						"id":                  p.ID,
						"path_with_namespace": p.PathWithNamespace,
						"web_url":             "https://gitlab.local/" + p.PathWithNamespace,
						"default_branch":      p.DefaultBranch,
						"visibility":          "private",
					})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestOrchestratorDryRun(t *testing.T) {
	mock := newMockGitLab()
	mock.projects["100"] = mockProject{
		ID:                100,
		PathWithNamespace: "org/vuln-project",
		DefaultBranch:     "main",
		CIContent: `stages: [test]
test:
  stage: test
  tags: [shell_exec]
  script:
    - echo $CI_MERGE_REQUEST_TITLE | sh
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
`,
	}

	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	orch, err := NewOrchestrator(srv.URL, "test-token", Options{
		InitialTargets: []string{"100"},
		DryRun:         true,
		FollowIncludes: false,
		FetchRunners:   false,
		Timeout:        10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOrchestrator() error = %v", err)
	}

	stats, err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if stats.ProjectsEnumerated != 1 {
		t.Errorf("ProjectsEnumerated = %d, want 1", stats.ProjectsEnumerated)
	}
	// In dry-run mode, no attacks should happen
	if stats.ProjectsAttacked != 0 {
		t.Errorf("ProjectsAttacked = %d, want 0 (dry-run)", stats.ProjectsAttacked)
	}
}

func TestOrchestratorMaxDepth(t *testing.T) {
	opts := Options{MaxDepth: 1}
	opts.defaults()
	if opts.MaxDepth != 1 {
		t.Errorf("MaxDepth after defaults = %d, want 1", opts.MaxDepth)
	}
}

func TestOrchestratorDefaults(t *testing.T) {
	opts := Options{}
	opts.defaults()
	if opts.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", opts.MaxDepth)
	}
	if opts.MaxTargets != 50 {
		t.Errorf("MaxTargets = %d, want 50", opts.MaxTargets)
	}
	if opts.AttackBranch != "gogatoz-pivot" {
		t.Errorf("AttackBranch = %q, want gogatoz-pivot", opts.AttackBranch)
	}
	if opts.ListenAddr != ":9443" {
		t.Errorf("ListenAddr = %q, want :9443", opts.ListenAddr)
	}
}

func TestFilterExploitable(t *testing.T) {
	t.Run("nil results", func(t *testing.T) {
		targets := filterExploitable(nil)
		if len(targets) != 0 {
			t.Errorf("filterExploitable(nil) = %d targets, want 0", len(targets))
		}
	})

	t.Run("with exploitable findings", func(t *testing.T) {
		results := []enumerate.Result{
			{
				ProjectID:         1,
				ProjectPathWithNS: "org/vuln",
				Findings: []analyze.Finding{
					{ID: "SELF_HOSTED_EXPOSED", Evidence: "tags=[shell_exec]"},
				},
			},
			{
				ProjectID:         2,
				ProjectPathWithNS: "org/safe",
				Findings: []analyze.Finding{
					{ID: "WORKFLOW_BROAD_RULES"}, // not exploitable
				},
			},
			{
				ProjectID:         3,
				ProjectPathWithNS: "org/vuln2",
				Findings: []analyze.Finding{
					{ID: "PLAINTEXT_SECRET"},
				},
			},
		}
		targets := filterExploitable(results)
		if len(targets) != 2 {
			t.Errorf("filterExploitable() = %d targets, want 2", len(targets))
		}
		if len(targets) > 0 && targets[0].Path != "org/vuln" {
			t.Errorf("targets[0].Path = %q, want org/vuln", targets[0].Path)
		}
	})

	t.Run("dedup by project", func(t *testing.T) {
		results := []enumerate.Result{
			{
				ProjectID:         1,
				ProjectPathWithNS: "org/vuln",
				Findings: []analyze.Finding{
					{ID: "SELF_HOSTED_EXPOSED"},
					{ID: "PLAINTEXT_SECRET"},
				},
			},
		}
		targets := filterExploitable(results)
		if len(targets) != 1 {
			t.Errorf("filterExploitable() = %d targets, want 1 (dedup)", len(targets))
		}
	})
}

func TestSplitTags(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"shell_exec,docker", 2},
		{"single", 1},
		{"", 0},
		{"a, b, c", 3},
	}
	for _, tt := range tests {
		got := splitTags(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitTags(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestOrchestratorProgressCallback(t *testing.T) {
	mock := newMockGitLab()
	mock.projects["100"] = mockProject{
		ID:                100,
		PathWithNamespace: "org/test",
		DefaultBranch:     "main",
	}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	var events []string
	orch, err := NewOrchestrator(srv.URL, "test-token", Options{
		InitialTargets: []string{"100"},
		DryRun:         true,
		Timeout:        10 * time.Second,
		Progress: func(e PivotEvent) {
			events = append(events, e.Type)
		},
	})
	if err != nil {
		t.Fatalf("NewOrchestrator() error = %v", err)
	}

	_, err = orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(events) == 0 {
		t.Error("expected progress events, got none")
	}

	// Should have at least depth_start and depth_end
	hasStart := false
	hasEnd := false
	for _, e := range events {
		if e == "depth_start" {
			hasStart = true
		}
		if e == "depth_end" {
			hasEnd = true
		}
	}
	if !hasStart {
		t.Error("missing depth_start event")
	}
	if !hasEnd {
		t.Error("missing depth_end event")
	}

	// Stats accessors
	stats := orch.Stats()
	if stats.ProjectsEnumerated != 1 {
		t.Errorf("Stats().ProjectsEnumerated = %d, want 1", stats.ProjectsEnumerated)
	}
	creds := orch.Credentials()
	if creds.Len() != 1 { // initial only
		t.Errorf("Credentials().Len() = %d, want 1", creds.Len())
	}
}
