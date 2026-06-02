package gitlabx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestListRepoTreePaths_PaginatesAndFiltersBlobs(t *testing.T) {
	var calls int
	var lastRef, lastPerPage, lastPage, lastToken, lastRecursive string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v4/projects/42/repository/tree" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		lastRef = q.Get("ref")
		lastPerPage = q.Get("per_page")
		lastPage = q.Get("page")
		lastRecursive = q.Get("recursive")
		lastToken = r.Header.Get("PRIVATE-TOKEN")
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			// first page: two entries and next page header
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode([]RepoTreeEntry{
				{Path: "README.md", Type: "blob"},
				{Path: "docs", Type: "tree"},
			})
			return
		}
		// second page: final entries
		_ = json.NewEncoder(w).Encode([]RepoTreeEntry{
			{Path: "docs/index.md", Type: "blob"},
			{Path: "src", Type: "tree"},
		})
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := cl.ListRepoTreePaths(context.Background(), 42, "main", true, 2, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 blob paths, got %d: %v", len(paths), paths)
	}
	if lastRef != "main" {
		t.Fatalf("expected ref main, got %q", lastRef)
	}
	if lastRecursive != "true" {
		t.Fatalf("expected recursive=true, got %q", lastRecursive)
	}
	if lastToken != "tok" {
		t.Fatalf("expected token header set, got %q", lastToken)
	}
	if lastPerPage != "2" {
		t.Fatalf("expected per_page=2, got %q", lastPerPage)
	}
	pg, _ := strconv.Atoi(lastPage)
	if pg != 2 {
		t.Fatalf("expected last observed page=2, got %d", pg)
	}
}

func TestListRepoTreePaths_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.ListRepoTreePaths(context.Background(), 1, "", true, 10, 1)
	if err == nil || !strings.Contains(err.Error(), "http 400") {
		t.Fatalf("expected http error, got %v", err)
	}
}
