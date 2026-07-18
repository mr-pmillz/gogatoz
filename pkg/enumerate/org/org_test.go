package org

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// fakeGroup is the minimal JSON the SDK needs to parse a group response.
type fakeGroup struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// fakeProject is the minimal JSON the SDK needs to parse a project response.
type fakeProject struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	DefaultBranch     string `json:"default_branch"`
}

func TestListAccessibleProjects_SinglePage(t *testing.T) {
	projects := []fakeProject{
		{ID: 1, PathWithNamespace: "user/proj-a"},
		{ID: 2, PathWithNamespace: "org/proj-b"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("membership") != "true" {
			t.Errorf("expected membership=true, got %q", r.URL.Query().Get("membership"))
		}
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "100")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", fmt.Sprintf("%d", len(projects)))
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer srv.Close()
	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	paths, err := ListAccessibleProjects(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	if paths[0] != "user/proj-a" || paths[1] != "org/proj-b" {
		t.Errorf("unexpected paths: %v", paths)
	}
}

func TestListAccessibleProjects_NilClient(t *testing.T) {
	_, err := ListAccessibleProjects(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected nil client error, got %v", err)
	}
}

func TestListAllProjects_MultiPage(t *testing.T) {
	page1 := []fakeProject{{ID: 1, PathWithNamespace: "a/one"}, {ID: 2, PathWithNamespace: "b/two"}}
	page2 := []fakeProject{{ID: 3, PathWithNamespace: "c/three"}}
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("membership") != "" {
			t.Errorf("--all-projects should NOT set membership, got %q", r.URL.Query().Get("membership"))
		}
		calls++
		if calls == 1 {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "2")
			w.Header().Set("X-Per-Page", "2")
			w.Header().Set("X-Total-Pages", "2")
			_ = json.NewEncoder(w).Encode(page1)
		} else {
			w.Header().Set("X-Page", "2")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "2")
			w.Header().Set("X-Total-Pages", "2")
			_ = json.NewEncoder(w).Encode(page2)
		}
	}))
	defer srv.Close()
	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	paths, err := ListAllProjects(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(paths), paths)
	}
}

func TestListAllProjects_NilClient(t *testing.T) {
	_, err := ListAllProjects(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected nil client error, got %v", err)
	}
}

func TestListGroupProjects_SinglePage(t *testing.T) {
	projects := []fakeProject{
		{ID: 10, PathWithNamespace: "org/proj-a", WebURL: "https://gl.test/org/proj-a", DefaultBranch: "main"},
		{ID: 11, PathWithNamespace: "org/proj-b", WebURL: "https://gl.test/org/proj-b", DefaultBranch: "main"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/projects"):
			// ListGroupProjects endpoint
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", fmt.Sprintf("%d", len(projects)))
			_ = json.NewEncoder(w).Encode(projects)
		case strings.Contains(r.URL.Path, "/groups/"):
			// GetGroup endpoint
			_ = json.NewEncoder(w).Encode(fakeGroup{ID: 5, Name: "org"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	paths, err := ListGroupProjects(context.Background(), client, 5, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
	if paths[0] != "org/proj-a" {
		t.Errorf("paths[0]: expected %q, got %q", "org/proj-a", paths[0])
	}
	if paths[1] != "org/proj-b" {
		t.Errorf("paths[1]: expected %q, got %q", "org/proj-b", paths[1])
	}
}

func TestListGroupProjects_MultiPage(t *testing.T) {
	page1 := []fakeProject{
		{ID: 10, PathWithNamespace: "org/proj-a", WebURL: "https://gl.test/org/proj-a", DefaultBranch: "main"},
		{ID: 11, PathWithNamespace: "org/proj-b", WebURL: "https://gl.test/org/proj-b", DefaultBranch: "main"},
	}
	page2 := []fakeProject{
		{ID: 12, PathWithNamespace: "org/proj-c", WebURL: "https://gl.test/org/proj-c", DefaultBranch: "main"},
	}

	var projectCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/projects"):
			projectCalls++
			if projectCalls == 1 {
				w.Header().Set("X-Page", "1")
				w.Header().Set("X-Next-Page", "2")
				w.Header().Set("X-Per-Page", "2")
				w.Header().Set("X-Total-Pages", "2")
				w.Header().Set("X-Total", "3")
				_ = json.NewEncoder(w).Encode(page1)
			} else {
				w.Header().Set("X-Page", "2")
				w.Header().Set("X-Next-Page", "")
				w.Header().Set("X-Per-Page", "2")
				w.Header().Set("X-Total-Pages", "2")
				w.Header().Set("X-Total", "3")
				_ = json.NewEncoder(w).Encode(page2)
			}
		case strings.Contains(r.URL.Path, "/groups/"):
			_ = json.NewEncoder(w).Encode(fakeGroup{ID: 5, Name: "org"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	paths, err := ListGroupProjects(context.Background(), client, 5, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(paths), paths)
	}
	want := []string{"org/proj-a", "org/proj-b", "org/proj-c"}
	for i, w := range want {
		if paths[i] != w {
			t.Errorf("paths[%d]: expected %q, got %q", i, w, paths[i])
		}
	}
}

func TestListGroupProjects_EmptyGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/projects"):
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "0")
			_ = json.NewEncoder(w).Encode([]fakeProject{})
		case strings.Contains(r.URL.Path, "/groups/"):
			_ = json.NewEncoder(w).Encode(fakeGroup{ID: 5, Name: "org"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	paths, err := ListGroupProjects(context.Background(), client, 5, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths, got %d: %v", len(paths), paths)
	}
}

func TestListGroupProjects_GroupNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"404 Group Not Found"}`))
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = ListGroupProjects(context.Background(), client, 9999, false)
	if err == nil {
		t.Fatalf("expected error for 404 group, got nil")
	}
}

func TestListGroupProjects_NilClient(t *testing.T) {
	_, err := ListGroupProjects(context.Background(), nil, 5, false)
	if err == nil {
		t.Fatalf("expected error for nil client, got nil")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected error containing 'nil client', got %q", err.Error())
	}
}
