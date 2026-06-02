package enumerate

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

func TestOptions_Defaults(t *testing.T) {
	opts := Options{}
	if opts.Concurrency != 0 {
		t.Errorf("expected default Concurrency=0, got %d", opts.Concurrency)
	}
	if opts.IncludeDepth != 0 {
		t.Errorf("expected default IncludeDepth=0, got %d", opts.IncludeDepth)
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"removes duplicates", []string{"a", "b", "a"}, []string{"a", "b"}},
		{"trims whitespace", []string{" a ", "a"}, []string{"a"}},
		{"skips comments", []string{"a", "#comment", "b"}, []string{"a", "b"}},
		{"skips empty", []string{"a", "", "  ", "b"}, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedup(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("dedup(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("dedup(%v)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestResult_Structure(t *testing.T) {
	r := Result{
		ProjectID:         123,
		ProjectPathWithNS: "group/project",
		WebURL:            "https://gitlab.com/group/project",
		DefaultBranch:     "main", //nolint:goconst // test value
		HasCIPipeline:     true,
		CISummary:         "stages=[build test] jobs=2",
	}
	if r.ProjectID != 123 {
		t.Errorf("expected ProjectID=123, got %d", r.ProjectID)
	}
	if r.ProjectPathWithNS != "group/project" {
		t.Errorf("expected path group/project, got %s", r.ProjectPathWithNS)
	}
	if !r.HasCIPipeline {
		t.Error("expected HasCIPipeline=true")
	}
}

// --- Integration-style tests against mock GitLab API ------------------------

const testCIYAML = `stages: [build]
build:
  stage: build
  script: [make build]
`

// newEnumMockServer creates an httptest server and gitlabx client for enumeration tests.
// serveCI controls whether the CI file endpoint returns content or 404.
func newEnumMockServer(t *testing.T, serveCI bool) (*gitlabx.Client, *httptest.Server) {
	t.Helper()
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(testCIYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GET /api/v4/projects/:id — return project metadata
		if strings.Contains(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			resp := map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// GET /api/v4/projects/:id/repository/files/:path
		if strings.Contains(r.URL.Path, "/repository/files/") {
			if !serveCI {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
				return
			}
			resp := map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		ts.Close()
		t.Fatalf("gitlabx.New: %v", err)
	}
	return cl, ts
}

func TestEnumerateProjects_ProgressCallback(t *testing.T) {
	cl, ts := newEnumMockServer(t, true)
	defer ts.Close()

	var count int64
	opts := Options{
		Concurrency: 2,
		SkipAnalyze: true,
		Progress: func(r Result) {
			atomic.AddInt64(&count, 1)
		},
	}

	idents := []string{"42", "42"} // second is a duplicate, will be deduped to 1
	results, err := EnumerateProjects(context.Background(), cl, idents, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (dedup), got %d", len(results))
	}
	if atomic.LoadInt64(&count) != 1 {
		t.Fatalf("expected progress called 1 time, got %d", atomic.LoadInt64(&count))
	}
}

func TestEnumerateProjects_NoCIFile(t *testing.T) {
	cl, ts := newEnumMockServer(t, false)
	defer ts.Close()

	opts := Options{Concurrency: 1, SkipAnalyze: true}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].HasCIPipeline {
		t.Fatal("expected HasCIPipeline=false when CI file is missing")
	}
	if results[0].CISummary != "no .gitlab-ci.yml" {
		t.Fatalf("expected CISummary='no .gitlab-ci.yml', got %q", results[0].CISummary)
	}
}

func TestEnumerateProjects_ParsesCI(t *testing.T) {
	cl, ts := newEnumMockServer(t, true)
	defer ts.Close()

	opts := Options{Concurrency: 1, SkipAnalyze: true}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.HasCIPipeline {
		t.Fatal("expected HasCIPipeline=true")
	}
	if r.CISummary == "" {
		t.Fatal("expected non-empty CISummary")
	}
	if r.ProjectID != 42 {
		t.Fatalf("expected ProjectID=42, got %d", r.ProjectID)
	}
	if r.DefaultBranch != "main" { //nolint:goconst // test value
		t.Fatalf("expected DefaultBranch=main, got %s", r.DefaultBranch)
	}
}

func TestEnumerateProjects_ProjectNotFound(t *testing.T) {
	// Server returns 404 for project lookup
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 Project Not Found"})
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	opts := Options{Concurrency: 1, SkipAnalyze: true}
	results, err := EnumerateProjects(context.Background(), cl, []string{"doesnt/exist"}, opts)
	if err != nil {
		t.Fatalf("enumerate returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == "" {
		t.Fatal("expected Error field to be set for project not found")
	}
	if !strings.Contains(results[0].Error, "get project") {
		t.Fatalf("expected error about get project, got %q", results[0].Error)
	}
}

func TestEnumerateProjects_ContextCancelled(t *testing.T) {
	cl, ts := newEnumMockServer(t, true)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	opts := Options{Concurrency: 1, SkipAnalyze: true}
	results, err := EnumerateProjects(ctx, cl, []string{"42"}, opts)
	// With a cancelled context, we expect either an error on results or a context error.
	// The function should not panic.
	if err != nil {
		// acceptable — context cancelled propagated
		return
	}
	// If no top-level error, each result should have an error
	for _, r := range results {
		if r.Error == "" {
			t.Fatal("expected per-result error with cancelled context, got none")
		}
	}
}

func TestEnumerateProjects_DefaultConcurrency(t *testing.T) {
	cl, ts := newEnumMockServer(t, true)
	defer ts.Close()

	// Concurrency: 0 should default to 8 and not panic
	opts := Options{Concurrency: 0, SkipAnalyze: true}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ProjectID != 42 {
		t.Fatalf("expected ProjectID=42, got %d", results[0].ProjectID)
	}
}

// --- scanOne coverage expansions --------------------------------------------

// testCIYAMLWithSecret has a plaintext secret for triggering analysis findings.
//
//nolint:gosec // G101: intentional test fixture with fake credentials
const testCIYAMLWithSecret = `stages: [build]
build:
  stage: build
  script:
    - echo "PASSWORD=supersecret123"
  variables:
    API_KEY: "hardcoded-plaintext-key-value"
`

// testCIYAMLWithInclude has a local include directive.
const testCIYAMLWithInclude = `stages: [build]
include:
  - local: deploy.yml
build:
  stage: build
  script: [make build]
`

// testIncludedYAML is the content returned for the included file.
const testIncludedYAML = `stages: [deploy]
deploy:
  stage: deploy
  script: [make deploy]
  tags: [prod]
`

func TestScanOne_FetchProtectedBranches(t *testing.T) {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(testCIYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Protected branches endpoint
		if strings.Contains(r.URL.Path, "/protected_branches") {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "2")
			json.NewEncoder(w).Encode([]map[string]any{
				{"name": "main"},
				{"name": "release/*"},
			})
			return
		}

		// GetProject
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			})
			return
		}

		// CI file
		if strings.Contains(r.URL.Path, "/repository/files/") {
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	opts := Options{
		Concurrency:    1,
		SkipAnalyze:    true,
		FetchProtected: true,
	}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if len(r.ProtectedBranches) != 2 {
		t.Fatalf("expected 2 protected branches, got %d: %v", len(r.ProtectedBranches), r.ProtectedBranches)
	}
	if r.ProtectedBranches[0] != "main" {
		t.Fatalf("expected first protected branch=main, got %s", r.ProtectedBranches[0])
	}
}

func TestScanOne_FetchRunners_ProjectScope(t *testing.T) {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(testCIYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Project runners endpoint
		if strings.Contains(r.URL.Path, "/runners") && !strings.Contains(r.URL.Path, "/all") {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "2")
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":          int64(1),
					"description": "shell runner",
					"paused":      false,
					"is_shared":   false,
					"online":      true,
					"status":      "online",
					"tag_list":    []string{"shell"},
				},
				{
					"id":          int64(2),
					"description": "docker runner",
					"paused":      false,
					"is_shared":   true,
					"online":      false,
					"status":      "offline",
					"tag_list":    []string{"docker"},
				},
			})
			return
		}

		// GetProject
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") && !strings.Contains(r.URL.Path, "/runners") {
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			})
			return
		}

		// CI file
		if strings.Contains(r.URL.Path, "/repository/files/") {
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	opts := Options{
		Concurrency:  1,
		SkipAnalyze:  true,
		FetchRunners: true,
		RunnerScope:  "project",
	}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.RunnerScope != "project" {
		t.Fatalf("expected RunnerScope=project, got %s", r.RunnerScope)
	}
	if r.RunnersTotal != 2 {
		t.Fatalf("expected RunnersTotal=2, got %d", r.RunnersTotal)
	}
	if r.RunnersOnline != 1 {
		t.Fatalf("expected RunnersOnline=1, got %d", r.RunnersOnline)
	}
}

func TestScanOne_WithAnalysis(t *testing.T) {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(testCIYAMLWithSecret))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GetProject
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			})
			return
		}

		// CI file
		if strings.Contains(r.URL.Path, "/repository/files/") {
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	opts := Options{
		Concurrency: 1,
		SkipAnalyze: false, // analysis enabled
	}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.HasCIPipeline {
		t.Fatal("expected HasCIPipeline=true")
	}
	// Analyzer should produce at least one finding for the plaintext secret
	if len(r.Findings) == 0 {
		t.Fatal("expected non-empty Findings from analysis with plaintext secret")
	}
}

func TestScanOne_Redaction(t *testing.T) {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(testCIYAMLWithSecret))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			})
			return
		}
		if strings.Contains(r.URL.Path, "/repository/files/") {
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	// testCIYAMLWithSecret declares a job-level API_KEY=hardcoded-plaintext-key-value.
	secretEvidence := func(t *testing.T, redact bool) string {
		t.Helper()
		results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, Options{Concurrency: 1, Redact: redact})
		if err != nil {
			t.Fatalf("enumerate: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		for _, f := range results[0].Findings {
			if f.ID == "PLAINTEXT_SECRET_JOB" {
				return f.Evidence
			}
		}
		t.Fatalf("expected PLAINTEXT_SECRET_JOB finding, got %+v", results[0].Findings)
		return ""
	}

	// Default: unredacted — the real value is present, no <redacted> marker.
	ev := secretEvidence(t, false)
	if !strings.Contains(ev, "hardcoded-plaintext-key-value") {
		t.Errorf("unredacted: expected real value in evidence, got %q", ev)
	}
	if strings.Contains(ev, "<redacted>") {
		t.Errorf("unredacted: did not expect <redacted> marker, got %q", ev)
	}

	// --redacted: value masked, real value absent.
	evR := secretEvidence(t, true)
	if !strings.Contains(evR, "API_KEY=<redacted>") {
		t.Errorf("redacted: expected API_KEY=<redacted>, got %q", evR)
	}
	if strings.Contains(evR, "hardcoded-plaintext-key-value") {
		t.Errorf("redacted: real value should be absent, got %q", evR)
	}
}

func TestScanOne_FollowIncludes(t *testing.T) {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(testCIYAMLWithInclude))
	includeEncoded := base64.StdEncoding.EncodeToString([]byte(testIncludedYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GetProject
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			})
			return
		}

		// Repository files — serve both .gitlab-ci.yml and deploy.yml
		if strings.Contains(r.URL.Path, "/repository/files/") {
			if strings.Contains(r.URL.Path, "deploy.yml") {
				json.NewEncoder(w).Encode(map[string]any{
					"file_name": "deploy.yml",
					"file_path": "deploy.yml",
					"encoding":  "base64",
					"content":   includeEncoded,
				})
				return
			}
			// Default: serve .gitlab-ci.yml
			json.NewEncoder(w).Encode(map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	opts := Options{
		Concurrency:    1,
		SkipAnalyze:    true,
		FollowIncludes: true,
		IncludeDepth:   2,
	}
	results, err := EnumerateProjects(context.Background(), cl, []string{"42"}, opts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.HasCIPipeline {
		t.Fatal("expected HasCIPipeline=true")
	}
	// CISummary should reflect the merged document, which includes the deploy stage
	if !strings.Contains(r.CISummary, "deploy") {
		t.Fatalf("expected CISummary to include 'deploy' from included file, got %q", r.CISummary)
	}
}
