package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// --- Test fixtures -------------------------------------------------------

//nolint:gosec // G101: intentional test fixture with fake credentials
const testCIYAMLWithSecret = `stages: [build]
build:
  stage: build
  script:
    - echo "PASSWORD=supersecret123"
  variables:
    API_KEY: "hardcoded-plaintext-key-value"
`

const testCIYAMLBasic = `stages: [build]
build:
  stage: build
  script: [make build]
`

// --- Mock GitLab servers -------------------------------------------------

type mockOpts struct {
	projects     []map[string]any // projects for ListProjects
	serveCI      bool             // whether to serve CI file
	langEndpoint bool             // whether to serve language endpoint
}

func newSearchMockGitLab(t *testing.T, opts mockOpts) (*gitlabx.Client, *httptest.Server) {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// ListProjects
		if r.URL.Path == "/api/v4/projects" {
			// Pagination headers
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "50")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", fmt.Sprintf("%d", len(opts.projects)))
			_ = json.NewEncoder(w).Encode(opts.projects)
			return
		}

		// Language endpoint
		if opts.langEndpoint && strings.Contains(r.URL.Path, "/languages") {
			_ = json.NewEncoder(w).Encode(map[string]float64{"Go": 80.0, "Shell": 20.0})
			return
		}

		// Path-exists (file check)
		if strings.Contains(r.URL.Path, "/repository/files/") {
			if opts.serveCI {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"file_name": ".gitlab-ci.yml",
					"file_path": ".gitlab-ci.yml",
					"encoding":  "base64",
					"content":   base64.StdEncoding.EncodeToString([]byte("test")),
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	cl, err := gitlabx.New(ts.URL, "test-token") //nolint:gosec // test value
	if err != nil {
		ts.Close()
		t.Fatalf("gitlabx.New: %v", err)
	}
	return cl, ts
}

func newEnumMockGitLab(t *testing.T, serveCI bool, ciYAML string) (*gitlabx.Client, *httptest.Server) {
	t.Helper()
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(ciYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GetProject
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/test-project",
				"web_url":             "https://gitlab.example.com/group/test-project",
				"default_branch":      "main",
			})
			return
		}

		// CI file
		if strings.Contains(r.URL.Path, "/repository/files/") {
			if !serveCI {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	cl, err := gitlabx.New(ts.URL, "test-token") //nolint:gosec // test value
	if err != nil {
		ts.Close()
		t.Fatalf("gitlabx.New: %v", err)
	}
	return cl, ts
}

// --- Search tool tests ---------------------------------------------------

func TestSearchProjects_BasicQuery(t *testing.T) {
	projects := []map[string]any{
		{
			"id": int64(1), "path_with_namespace": "group/alpha",
			"web_url": "https://gitlab.com/group/alpha", "visibility": "public",
			"default_branch": "main", "topics": []string{},
		},
		{
			"id": int64(2), "path_with_namespace": "group/beta",
			"web_url": "https://gitlab.com/group/beta", "visibility": "internal",
			"default_branch": "develop", "topics": []string{},
		},
	}
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: projects})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	input := searchInput{Query: "test"}
	_, out, err := srv.handleSearchProjects(context.Background(), nil, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("expected 2 projects, got %d", out.Total)
	}
	if out.Projects[0].PathWithNamespace != "group/alpha" {
		t.Fatalf("expected group/alpha, got %s", out.Projects[0].PathWithNamespace)
	}
	if out.Projects[1].Visibility != "internal" { //nolint:goconst // test value
		t.Fatalf("expected visibility=internal, got %s", out.Projects[1].Visibility)
	}
}

func TestSearchProjects_EmptyResults(t *testing.T) {
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: []map[string]any{}})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, out, err := srv.handleSearchProjects(context.Background(), nil, searchInput{Query: "nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 0 {
		t.Fatalf("expected 0 projects, got %d", out.Total)
	}
	if len(out.Projects) != 0 {
		t.Fatalf("expected empty projects slice, got %d", len(out.Projects))
	}
}

func TestSearchProjects_InvalidVisibility(t *testing.T) {
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: []map[string]any{}})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, _, err := srv.handleSearchProjects(context.Background(), nil, searchInput{Visibility: "bogus"})
	if err == nil {
		t.Fatal("expected error for invalid visibility")
	}
	if !strings.Contains(err.Error(), "invalid visibility") {
		t.Fatalf("expected 'invalid visibility' in error, got %q", err.Error())
	}
}

func TestSearchProjects_TopicFilter(t *testing.T) {
	projects := []map[string]any{
		{
			"id": int64(1), "path_with_namespace": "group/sec",
			"web_url": "https://gitlab.com/group/sec", "visibility": "public",
			"default_branch": "main", "topics": []string{"security", "ci"},
		},
		{
			"id": int64(2), "path_with_namespace": "group/web",
			"web_url": "https://gitlab.com/group/web", "visibility": "public",
			"default_branch": "main", "topics": []string{"frontend"},
		},
	}
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: projects})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, out, err := srv.handleSearchProjects(context.Background(), nil, searchInput{Topic: "security"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 project after topic filter, got %d", out.Total)
	}
	if out.Projects[0].PathWithNamespace != "group/sec" {
		t.Fatalf("expected group/sec, got %s", out.Projects[0].PathWithNamespace)
	}
}

func TestSearchProjects_LanguageFilter(t *testing.T) {
	projects := []map[string]any{
		{
			"id": int64(1), "path_with_namespace": "group/goapp",
			"web_url": "https://gitlab.com/group/goapp", "visibility": "public",
			"default_branch": "main", "topics": []string{},
		},
	}
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: projects, langEndpoint: true})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, out, err := srv.handleSearchProjects(context.Background(), nil, searchInput{Language: "go"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 project for go language, got %d", out.Total)
	}
}

func TestSearchProjects_PathExistsFilter(t *testing.T) {
	projects := []map[string]any{
		{
			"id": int64(1), "path_with_namespace": "group/withci",
			"web_url": "https://gitlab.com/group/withci", "visibility": "public",
			"default_branch": "main", "topics": []string{},
		},
	}
	// serveCI=true means path-exists will find the file
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: projects, serveCI: true})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, out, err := srv.handleSearchProjects(context.Background(), nil, searchInput{PathExists: ".gitlab-ci.yml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 project with path, got %d", out.Total)
	}
}

func TestSearchProjects_PathExistsFilter_NotFound(t *testing.T) {
	projects := []map[string]any{
		{
			"id": int64(1), "path_with_namespace": "group/noci",
			"web_url": "https://gitlab.com/group/noci", "visibility": "public",
			"default_branch": "main", "topics": []string{},
		},
	}
	// serveCI=false means path-exists will 404
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: projects, serveCI: false})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, out, err := srv.handleSearchProjects(context.Background(), nil, searchInput{PathExists: ".gitlab-ci.yml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 0 {
		t.Fatalf("expected 0 projects (file not found), got %d", out.Total)
	}
}

// --- Enumerate tool tests ------------------------------------------------

func TestEnumerateProjects_SingleProject(t *testing.T) {
	cl, ts := newEnumMockGitLab(t, true, testCIYAMLBasic)
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	input := enumerateInput{
		Projects:    []string{"42"},
		Concurrency: 1,
	}
	_, out, err := srv.handleEnumerateProjects(context.Background(), nil, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TotalScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", out.TotalScanned)
	}
	if out.Results[0].ProjectID != 42 {
		t.Fatalf("expected ProjectID=42, got %d", out.Results[0].ProjectID)
	}
	if !out.Results[0].HasCIPipeline {
		t.Fatal("expected HasCIPipeline=true")
	}
}

func TestEnumerateProjects_EmptyList(t *testing.T) {
	cl, ts := newEnumMockGitLab(t, false, "")
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	_, _, err := srv.handleEnumerateProjects(context.Background(), nil, enumerateInput{Projects: nil})
	if err == nil {
		t.Fatal("expected error for empty projects list")
	}
	if !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("expected 'non-empty' in error, got %q", err.Error())
	}
}

func TestEnumerateProjects_NoCIFile(t *testing.T) {
	cl, ts := newEnumMockGitLab(t, false, "")
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	input := enumerateInput{Projects: []string{"42"}, Concurrency: 1}
	_, out, err := srv.handleEnumerateProjects(context.Background(), nil, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TotalScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", out.TotalScanned)
	}
	if out.Results[0].HasCIPipeline {
		t.Fatal("expected HasCIPipeline=false when CI file is missing")
	}
}

func TestEnumerateProjects_InvalidTimeout(t *testing.T) {
	cl, ts := newEnumMockGitLab(t, false, "")
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	input := enumerateInput{Projects: []string{"42"}, Timeout: "not-a-duration"}
	_, _, err := srv.handleEnumerateProjects(context.Background(), nil, input)
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), "invalid timeout") {
		t.Fatalf("expected 'invalid timeout' in error, got %q", err.Error())
	}
}

func TestEnumerateProjects_WithFindings(t *testing.T) {
	cl, ts := newEnumMockGitLab(t, true, testCIYAMLWithSecret)
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	input := enumerateInput{Projects: []string{"42"}, Concurrency: 1}
	_, out, err := srv.handleEnumerateProjects(context.Background(), nil, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TotalScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", out.TotalScanned)
	}
	r := out.Results[0]
	if r.FindingsCount == 0 {
		t.Fatal("expected findings for CI YAML with plaintext secret")
	}
	if out.WithFindings != 1 {
		t.Fatalf("expected WithFindings=1, got %d", out.WithFindings)
	}
	// Verify finding structure
	found := false
	for _, f := range r.Findings {
		if f.Severity != "" && f.Title != "" && f.ID != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected at least one finding with non-empty Severity, Title, and ID")
	}
}

func TestNew_RegistersTools(t *testing.T) {
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: []map[string]any{}})
	defer ts.Close()

	srv := New(cl, nil, ts.URL)
	if srv.mcpSrv == nil {
		t.Fatal("expected non-nil MCP server")
	}
	if srv.client != cl {
		t.Fatal("expected client to be set")
	}
}

// --- Store-enabled tests -------------------------------------------------

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSearchProjects_WithStore(t *testing.T) {
	projects := []map[string]any{
		{
			"id": int64(1), "path_with_namespace": "group/alpha",
			"web_url": "https://gitlab.com/group/alpha", "visibility": "public",
			"default_branch": "main", "topics": []string{},
		},
	}
	cl, ts := newSearchMockGitLab(t, mockOpts{projects: projects})
	defer ts.Close()

	st := openTestStore(t)
	srv := New(cl, st, ts.URL)

	_, out, err := srv.handleSearchProjects(context.Background(), nil, searchInput{Query: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 project, got %d", out.Total)
	}

	// Verify stored in database.
	sessions, err := st.ListSessions(10)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].SearchTotal != 1 {
		t.Errorf("SearchTotal = %d, want 1", sessions[0].SearchTotal)
	}

	session, err := st.GetSession(sessions[0].ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(session.SearchResults) != 1 {
		t.Fatalf("SearchResults count = %d, want 1", len(session.SearchResults))
	}
	if session.SearchResults[0].PathWithNamespace != "group/alpha" {
		t.Errorf("PathWithNamespace = %q, want %q", session.SearchResults[0].PathWithNamespace, "group/alpha")
	}
}

func TestEnumerateProjects_WithStore(t *testing.T) {
	cl, ts := newEnumMockGitLab(t, true, testCIYAMLWithSecret)
	defer ts.Close()

	st := openTestStore(t)
	srv := New(cl, st, ts.URL)

	input := enumerateInput{Projects: []string{"42"}, Concurrency: 1}
	_, out, err := srv.handleEnumerateProjects(context.Background(), nil, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TotalScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", out.TotalScanned)
	}

	// Verify stored in database.
	sessions, err := st.ListSessions(10)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].EnumTotal != 1 {
		t.Errorf("EnumTotal = %d, want 1", sessions[0].EnumTotal)
	}

	session, err := st.GetSession(sessions[0].ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(session.EnumerateResults) != 1 {
		t.Fatalf("EnumerateResults count = %d, want 1", len(session.EnumerateResults))
	}
	er := session.EnumerateResults[0]
	if er.GitLabProjectID != 42 {
		t.Errorf("GitLabProjectID = %d, want 42", er.GitLabProjectID)
	}
	if len(er.Findings) == 0 {
		t.Fatal("expected findings stored in database")
	}
}
