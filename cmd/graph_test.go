package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/spf13/cobra"
)

const graphTestYAML = `
stages:
  - build
  - test
compile:
  stage: build
  script: echo compile
unit_test:
  stage: test
  script: echo test
  needs: [compile]
`

func newGraphMockServer(t *testing.T) (*gitlabx.Client, *httptest.Server) {
	t.Helper()

	b64Content := base64.StdEncoding.EncodeToString([]byte(graphTestYAML))

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v4/projects/42", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"id":             42,
			"default_branch": "main",
		})
	})

	mux.HandleFunc("/api/v4/projects/42/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"file_name": ".gitlab-ci.yml",
			"content":   b64Content,
			"encoding":  "base64",
		})
	})

	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyproject", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"id":             42,
			"default_branch": "main",
		})
	})

	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyproject/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"file_name": ".gitlab-ci.yml",
			"content":   b64Content,
			"encoding":  "base64",
		})
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	return cl, ts
}

func runGraphWithMock(t *testing.T, ts *httptest.Server, project, format, ref string) (string, error) {
	t.Helper()

	oldURL := gitlabURL
	oldToken := token
	gitlabURL = ts.URL
	token = "test-token"
	defer func() {
		gitlabURL = oldURL
		token = oldToken
	}()

	graphProject = project
	graphFormat = format
	graphRef = ref
	graphOutput = ""
	graphFollowIncludes = false
	graphIncludeDepth = 2
	graphSession = 0
	graphAllProjects = false

	cmd := &cobra.Command{Use: "test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := runGraph(cmd, nil)
	return buf.String(), err
}

func TestRunGraph_DOTByID(t *testing.T) {
	_, ts := newGraphMockServer(t)

	out, err := runGraphWithMock(t, ts, "42", "dot", "main")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if !strings.Contains(out, "digraph pipeline {") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(out, `"compile" -> "unit_test"`) {
		t.Error("missing compile -> unit_test edge")
	}
	if !strings.Contains(out, "cluster_build") {
		t.Error("missing build stage cluster")
	}
}

func TestRunGraph_MermaidByPath(t *testing.T) {
	_, ts := newGraphMockServer(t)

	out, err := runGraphWithMock(t, ts, "mygroup/myproject", "mermaid", "main")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if !strings.Contains(out, "flowchart LR") {
		t.Error("missing flowchart header")
	}
	if !strings.Contains(out, "compile --> unit_test") {
		t.Error("missing compile --> unit_test edge")
	}
}

func TestRunGraph_DefaultRef(t *testing.T) {
	_, ts := newGraphMockServer(t)

	out, err := runGraphWithMock(t, ts, "42", "dot", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if !strings.Contains(out, "digraph pipeline {") {
		t.Error("missing DOT output when using default ref")
	}
}

func TestRunGraph_InvalidFormat(t *testing.T) {
	_, ts := newGraphMockServer(t)

	_, err := runGraphWithMock(t, ts, "42", "svg", "main")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error = %q, want 'unknown format'", err.Error())
	}
}

func TestRunGraph_MissingToken(t *testing.T) {
	oldToken := token
	oldNoToken := noToken
	token = ""
	noToken = false
	defer func() {
		token = oldToken
		noToken = oldNoToken
	}()

	graphProject = "42"
	graphFormat = "dot"
	graphRef = "main"
	graphOutput = ""

	cmd := &cobra.Command{Use: "test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := runGraph(cmd, nil)
	if err == nil {
		t.Fatal("expected error when token is missing")
	}
	if !strings.Contains(err.Error(), "token required") {
		t.Errorf("error = %q, want 'token required'", err.Error())
	}
}

func TestRunGraph_NoModeSelected(t *testing.T) {
	oldToken := token
	token = "test-token"
	defer func() { token = oldToken }()

	graphProject = ""
	graphSession = 0
	graphAllProjects = false
	graphFormat = "dot"

	cmd := &cobra.Command{Use: "test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := runGraph(cmd, nil)
	if err == nil {
		t.Fatal("expected error when no mode selected")
	}
	if !strings.Contains(err.Error(), "one of") {
		t.Errorf("error = %q, want 'one of' message", err.Error())
	}
}

func TestRunGraph_CrossProjectWithMock(t *testing.T) {
	b64A := base64.StdEncoding.EncodeToString([]byte(`
stages: [build]
include:
  - project: group/project-b
    file: /ci.yml
build:
  stage: build
  script: echo build
`))
	b64B := base64.StdEncoding.EncodeToString([]byte(`
stages: [build]
build:
  stage: build
  script: echo build
`))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "default_branch": "main"}) //nolint:errcheck
	})
	mux.HandleFunc("/api/v4/projects/1/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"content": b64A, "encoding": "base64"}) //nolint:errcheck
	})
	mux.HandleFunc("/api/v4/projects/2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 2, "default_branch": "main"}) //nolint:errcheck
	})
	mux.HandleFunc("/api/v4/projects/2/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"content": b64B, "encoding": "base64"}) //nolint:errcheck
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	oldURL := gitlabURL
	oldToken := token
	gitlabURL = ts.URL
	token = "test-token"
	defer func() {
		gitlabURL = oldURL
		token = oldToken
	}()

	// Create in-memory DB with test data
	tmpDB := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(tmpDB)
	if err != nil {
		t.Fatal(err)
	}
	session := &store.ScanSession{GitLabURL: ts.URL}
	if err := st.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveEnumerateResults(session.ID, []store.EnumerateResult{
		{GitLabProjectID: 1, PathWithNamespace: "group/project-a", DefaultBranch: "main", HasCIPipeline: true},
		{GitLabProjectID: 2, PathWithNamespace: "group/project-b", DefaultBranch: "main", HasCIPipeline: true},
	}); err != nil {
		t.Fatal(err)
	}

	oldStore := cliStore
	cliStore = st
	defer func() { cliStore = oldStore }()

	graphProject = ""
	graphSession = session.ID
	graphAllProjects = false
	graphFormat = "dot"
	graphOutput = ""
	graphFollowIncludes = false

	cmd := &cobra.Command{Use: "test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := runGraph(cmd, nil); err != nil {
		t.Fatalf("error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "digraph cross_project {") {
		t.Error("missing cross_project digraph header")
	}
	if !strings.Contains(out, `"group/project-a"`) {
		t.Error("missing project-a node")
	}
	if !strings.Contains(out, `"group/project-b"`) {
		t.Error("missing project-b node")
	}
	if !strings.Contains(out, `"group/project-a" -> "group/project-b"`) {
		t.Error("missing include edge from project-a to project-b")
	}
	if !strings.Contains(out, `label="include"`) {
		t.Error("missing include edge label")
	}
}

func TestResolveProjectID_Numeric(t *testing.T) {
	got := resolveProjectID("12345")
	if id, ok := got.(int64); !ok || id != 12345 {
		t.Errorf("resolveProjectID(\"12345\") = %v (%T), want int64(12345)", got, got)
	}
}

func TestResolveProjectID_Path(t *testing.T) {
	got := resolveProjectID("mygroup/myproject")
	if s, ok := got.(string); !ok || s != "mygroup/myproject" {
		t.Errorf("resolveProjectID(\"mygroup/myproject\") = %v (%T), want string", got, got)
	}
}
