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

func TestCodeSearch_ErrOnEmptyQuery(t *testing.T) {
	cl, err := New("https://example.invalid", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.CodeSearch(context.Background(), 123, "", "", 10, 1); err == nil {
		t.Fatalf("expected error on empty query")
	}
}

func TestCodeSearch_PaginatesViaHeader(t *testing.T) {
	var calls int
	var seenToken, seenScope, seenSearch, seenRef string
	var seenPerPage, seenPage string
	// fake server mimicking GitLab API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v4/projects/123/search" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		seenToken = r.Header.Get("PRIVATE-TOKEN")
		seenScope = q.Get("scope")
		seenSearch = q.Get("search")
		seenRef = q.Get("ref")
		seenPerPage = q.Get("per_page")
		seenPage = q.Get("page")

		w.Header().Set("Content-Type", "application/json")
		// First page: indicate there is a next page via X-Next-Page
		if calls == 1 {
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode([]CodeSearchMatch{
				{Path: "a.go", Filename: "a.go", Startline: 1, Data: "foo"},
				{Path: "b.go", Filename: "b.go", Startline: 2, Data: "bar"},
			})
			return
		}
		// Second (last) page
		_ = json.NewEncoder(w).Encode([]CodeSearchMatch{
			{Path: "c.go", Filename: "c.go", Startline: 3, Data: "baz"},
		})
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "t0k3n")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := cl.CodeSearch(context.Background(), 123, "curl|bash", "main", 2, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(matches))
	}
	if seenToken != "t0k3n" {
		t.Fatalf("expected PRIVATE-TOKEN header to be set, got %q", seenToken)
	}
	if seenScope != "blobs" {
		t.Fatalf("expected scope=blobs, got %q", seenScope)
	}
	if seenSearch != "curl|bash" {
		t.Fatalf("expected search query propagated, got %q", seenSearch)
	}
	if seenRef != "main" {
		t.Fatalf("expected ref=main, got %q", seenRef)
	}
	if seenPerPage != "2" {
		t.Fatalf("expected per_page=2, got %q", seenPerPage)
	}
	pg, _ := strconv.Atoi(seenPage)
	if pg != 1 {
		t.Fatalf("expected first observed page=1, got %d", pg)
	}
}

func TestCodeSearch_HTTPErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer srv.Close()
	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.CodeSearch(context.Background(), 1, "x", "", 10, 1)
	if err == nil || !strings.Contains(err.Error(), "http 400") {
		t.Fatalf("expected http error surfaced, got %v", err)
	}
}
