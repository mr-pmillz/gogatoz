package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func postJSON(url string, body any) (*http.Response, error) {
	b, _ := json.Marshal(body)
	return http.Post(url, "application/json", bytes.NewReader(b)) //nolint:gosec // test helper, URL comes from httptest
}

// newTestServer builds an API Server with the default config and returns the
// httptest server. Caller must defer ts.Close().
func newTestServer() (*Server, *httptest.Server) {
	s := NewServer(Config{BaseURL: "https://gitlab.com"})
	ts := httptest.NewServer(s.engine)
	return s, ts
}

// newMockGitLab creates a fake GitLab API server that can answer project and CI file requests.
// Caller must defer ts.Close().
func newMockGitLab() *httptest.Server {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte("stages: [build]\nbuild:\n  stage: build\n  script: [make build]\n"))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GET /api/v4/user
		if r.URL.Path == "/api/v4/user" {
			json.NewEncoder(w).Encode(map[string]any{
				"id":       1,
				"username": "admin",
				"name":     "Admin User",
			})
			return
		}

		// GET /api/v4/projects/:id (not repository sub-path)
		if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			// Extract the project ident from the URL path
			ident := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/")
			ident = strings.ReplaceAll(ident, "%2F", "/")
			json.NewEncoder(w).Encode(map[string]any{
				"id":                  int64(42),
				"path_with_namespace": ident,
				"web_url":             "https://gitlab.example.com/" + ident,
				"default_branch":      "main",
			})
			return
		}

		// GET /api/v4/projects/:id/repository/files/:path
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
}

// --- Healthz ----------------------------------------------------------------

func TestHealthz(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["ok"] != true {
		t.Fatalf("expected ok=true, got %v", m["ok"])
	}
}

// --- /auth/validate ---------------------------------------------------------

func TestHandleValidate_MissingToken(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/auth/validate", map[string]any{
		"token": "",
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleValidate_Success(t *testing.T) {
	glSrv := newMockGitLab()
	defer glSrv.Close()

	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/auth/validate", map[string]any{
		"token":      "tok",
		"gitlab_url": glSrv.URL,
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["ok"] != true {
		t.Fatalf("expected ok=true, got %v", m)
	}
	usr, ok := m["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected user object, got %T", m["user"])
	}
	if usr["username"] != "admin" {
		t.Fatalf("expected username=admin, got %v", usr["username"])
	}
}

// --- /enumerate/repo --------------------------------------------------------

func TestHandleEnumerateRepo_MissingIdent(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/enumerate/repo", map[string]any{
		"auth":  map[string]any{"token": "tok"},
		"ident": "",
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleEnumerateRepo_MissingToken(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/enumerate/repo", map[string]any{
		"auth":  map[string]any{"token": ""},
		"ident": "group/project",
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleEnumerateRepo_Success(t *testing.T) {
	glSrv := newMockGitLab()
	defer glSrv.Close()

	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/enumerate/repo", map[string]any{
		"auth":  map[string]any{"token": "tok", "gitlab_url": glSrv.URL},
		"ident": "42",
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var results []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	pid, _ := results[0]["project_id"].(float64)
	if int64(pid) != 42 {
		t.Fatalf("expected project_id=42, got %v", results[0]["project_id"])
	}
	if results[0]["has_ci_pipeline"] != true {
		t.Fatalf("expected has_ci_pipeline=true, got %v", results[0]["has_ci_pipeline"])
	}
}

// --- /enumerate/repos -------------------------------------------------------

func TestHandleEnumerateRepos_Success(t *testing.T) {
	glSrv := newMockGitLab()
	defer glSrv.Close()

	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/enumerate/repos", map[string]any{
		"auth":   map[string]any{"token": "tok", "gitlab_url": glSrv.URL},
		"idents": []string{"42", "43"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var results []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r["has_ci_pipeline"] != true {
			t.Fatalf("result[%d]: expected has_ci_pipeline=true, got %v", i, r["has_ci_pipeline"])
		}
	}
}

func TestHandleEnumerateRepos_EmptyIdents(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/enumerate/repos", map[string]any{
		"auth":   map[string]any{"token": "tok"},
		"idents": []string{},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// --- /search/projects -------------------------------------------------------

// newSearchMockGitLab creates a fake GitLab API server for project search tests.
// It serves the /api/v4/projects endpoint with pagination headers and optional
// topic/language support.
func newSearchMockGitLab(projects []map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GET /api/v4/user — auth check
		if r.URL.Path == "/api/v4/user" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 1, "username": "admin", "name": "Admin User",
			})
			return
		}

		// GET /api/v4/projects — list projects
		if r.URL.Path == "/api/v4/projects" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "50")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", fmt.Sprintf("%d", len(projects)))
			_ = json.NewEncoder(w).Encode(projects)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestHandleSearchProjects_MissingToken(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/search/projects", map[string]any{
		"auth":    map[string]any{"token": ""},
		"options": map[string]any{},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleSearchProjects_InvalidVisibility(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/search/projects", map[string]any{
		"auth":    map[string]any{"token": "tok"},
		"options": map[string]any{"visibility": "bogus"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleSearchProjects_BasicQuery(t *testing.T) {
	glSrv := newSearchMockGitLab([]map[string]any{
		{
			"id": 10, "path_with_namespace": "org/alpha",
			"web_url": "https://gl.example.com/org/alpha", "visibility": "public",
			"default_branch": "main", "archived": false, "topics": []string{},
		},
		{
			"id": 20, "path_with_namespace": "org/beta",
			"web_url": "https://gl.example.com/org/beta", "visibility": "private",
			"default_branch": "develop", "archived": false, "topics": []string{},
		},
	})
	defer glSrv.Close()

	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/search/projects", map[string]any{
		"auth":    map[string]any{"token": "tok", "gitlab_url": glSrv.URL},
		"options": map[string]any{"query": "org"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body searchProjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TotalFound != 2 {
		t.Fatalf("expected total_found=2, got %d", body.TotalFound)
	}
	if body.Returned != 2 {
		t.Fatalf("expected returned=2, got %d", body.Returned)
	}
	if len(body.Projects) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(body.Projects))
	}
	// check that project IDs are present
	ids := map[int64]bool{}
	for _, p := range body.Projects {
		ids[p.ID] = true
	}
	if !ids[10] || !ids[20] {
		t.Fatalf("expected project IDs 10 and 20, got %v", ids)
	}
}

func TestHandleSearchProjects_TopicFilter(t *testing.T) {
	glSrv := newSearchMockGitLab([]map[string]any{
		{
			"id": 10, "path_with_namespace": "org/alpha",
			"web_url": "https://gl.example.com/org/alpha", "visibility": "public",
			"default_branch": "main", "archived": false, "topics": []string{"security", "ci"},
		},
		{
			"id": 20, "path_with_namespace": "org/beta",
			"web_url": "https://gl.example.com/org/beta", "visibility": "public",
			"default_branch": "main", "archived": false, "topics": []string{"devops"},
		},
		{
			"id": 30, "path_with_namespace": "org/gamma",
			"web_url": "https://gl.example.com/org/gamma", "visibility": "public",
			"default_branch": "main", "archived": false, "topics": []string{"Security", "golang"},
		},
	})
	defer glSrv.Close()

	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/search/projects", map[string]any{
		"auth":    map[string]any{"token": "tok", "gitlab_url": glSrv.URL},
		"options": map[string]any{"topic": "security"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body searchProjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// should match projects 10 and 30 (case-insensitive topic match)
	if body.Returned != 2 {
		t.Fatalf("expected returned=2, got %d", body.Returned)
	}
	ids := map[int64]bool{}
	for _, p := range body.Projects {
		ids[p.ID] = true
	}
	if !ids[10] || !ids[30] {
		t.Fatalf("expected project IDs 10 and 30, got %v", ids)
	}
}

func TestHandleSearchProjects_EmptyResults(t *testing.T) {
	glSrv := newSearchMockGitLab([]map[string]any{})
	defer glSrv.Close()

	_, ts := newTestServer()
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/search/projects", map[string]any{
		"auth":    map[string]any{"token": "tok", "gitlab_url": glSrv.URL},
		"options": map[string]any{"query": "nonexistent"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body searchProjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TotalFound != 0 {
		t.Fatalf("expected total_found=0, got %d", body.TotalFound)
	}
	if body.Returned != 0 {
		t.Fatalf("expected returned=0, got %d", body.Returned)
	}
	if len(body.Projects) != 0 {
		t.Fatalf("expected 0 projects, got %d", len(body.Projects))
	}
}

func TestHandleSearchProjects_FakeSearchFn(t *testing.T) {
	s := NewServer(Config{BaseURL: "https://gitlab.com"})
	// inject a fake searchFn that returns a canned result
	s.searchFn = func(_ context.Context, _ *gitlabx.Client, opts searchProjectsOptions) ([]searchProjectResult, error) {
		if opts.Query != "test-query" {
			t.Fatalf("expected query=test-query, got %q", opts.Query)
		}
		return []searchProjectResult{
			{ID: 99, PathWithNamespace: "fake/project", WebURL: "https://fake.dev/fake/project", Visibility: "internal", DefaultBranch: "main"},
		}, nil
	}
	ts := httptest.NewServer(s.engine)
	defer ts.Close()

	resp, err := postJSON(ts.URL+"/search/projects", map[string]any{
		"auth":    map[string]any{"token": "tok"},
		"options": map[string]any{"query": "test-query"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body searchProjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Returned != 1 {
		t.Fatalf("expected returned=1, got %d", body.Returned)
	}
	if body.Projects[0].ID != 99 {
		t.Fatalf("expected ID=99, got %d", body.Projects[0].ID)
	}
	if body.Projects[0].PathWithNamespace != "fake/project" {
		t.Fatalf("expected path_with_namespace=fake/project, got %s", body.Projects[0].PathWithNamespace)
	}
}
