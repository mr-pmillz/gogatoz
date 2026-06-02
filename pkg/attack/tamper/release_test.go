package tamper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func testClient(t *testing.T, handler http.Handler) *gitlabx.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := gitlabx.New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	return client
}

func paginationHeaders(w http.ResponseWriter, page, nextPage, perPage, totalPages, total int64) {
	h := w.Header()
	h.Set("X-Page", fmt.Sprintf("%d", page))
	if nextPage > 0 {
		h.Set("X-Next-Page", fmt.Sprintf("%d", nextPage))
	}
	h.Set("X-Per-Page", fmt.Sprintf("%d", perPage))
	h.Set("X-Total-Pages", fmt.Sprintf("%d", totalPages))
	h.Set("X-Total", fmt.Sprintf("%d", total))
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode json: %v", err)
	}
}

func TestListReleases_Success(t *testing.T) {
	releases := []*gitlab.Release{
		{TagName: "v1.0.0", Name: "Release 1.0", Description: "First release"},
		{TagName: "v2.0.0", Name: "Release 2.0", Description: "Second release"},
	}

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/releases") {
			http.NotFound(w, r)
			return
		}
		paginationHeaders(w, 1, 0, 20, 1, 2)
		writeJSON(t, w, releases)
	}))

	result, err := ListReleases(context.Background(), client, 42)
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 releases, got %d", len(result))
	}
	if result[0].TagName != "v1.0.0" {
		t.Errorf("expected tag v1.0.0, got %s", result[0].TagName)
	}
	if result[1].Name != "Release 2.0" {
		t.Errorf("expected name 'Release 2.0', got %s", result[1].Name)
	}
}

func TestListReleaseLinks_Success(t *testing.T) {
	links := []*gitlab.ReleaseLink{
		{ID: 1, Name: "binary-linux", URL: "https://example.com/binary-linux"},
		{ID: 2, Name: "binary-mac", URL: "https://example.com/binary-mac"},
	}

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/links") {
			http.NotFound(w, r)
			return
		}
		paginationHeaders(w, 1, 0, 20, 1, 2)
		writeJSON(t, w, links)
	}))

	result, err := ListReleaseLinks(context.Background(), client, 42, "v1.0.0")
	if err != nil {
		t.Fatalf("ListReleaseLinks: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 links, got %d", len(result))
	}
	if result[0].Name != "binary-linux" {
		t.Errorf("expected name 'binary-linux', got %s", result[0].Name)
	}
	if result[1].ID != 2 {
		t.Errorf("expected ID 2, got %d", result[1].ID)
	}
}

func TestTamperRelease_UpdateMetadata(t *testing.T) {
	var gotPut bool

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/releases/v1.0.0") {
			gotPut = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body["name"] != "Tampered Release" {
				t.Errorf("expected name 'Tampered Release', got %v", body["name"])
			}
			if body["description"] != "Modified description" {
				t.Errorf("expected description 'Modified description', got %v", body["description"])
			}
			release := &gitlab.Release{
				TagName:     "v1.0.0",
				Name:        "Tampered Release",
				Description: "Modified description",
			}
			paginationHeaders(w, 1, 0, 20, 1, 1)
			writeJSON(t, w, release)
			return
		}
		http.NotFound(w, r)
	}))

	replaced, added, err := TamperRelease(context.Background(), client, 42, "v1.0.0", TamperReleaseOptions{
		NewName:        "Tampered Release",
		NewDescription: "Modified description",
	})
	if err != nil {
		t.Fatalf("TamperRelease: %v", err)
	}
	if !gotPut {
		t.Error("expected PUT request to update release")
	}
	if replaced != 0 || added != 0 {
		t.Errorf("expected 0 replaced/added, got %d/%d", replaced, added)
	}
}

func TestTamperRelease_ReplaceLink(t *testing.T) {
	var deleteCalled, createCalled bool

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// List links
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/links"):
			links := []*gitlab.ReleaseLink{
				{ID: 10, Name: "binary-linux", URL: "https://example.com/old-binary"},
				{ID: 11, Name: "binary-mac", URL: "https://example.com/mac-binary"},
			}
			paginationHeaders(w, 1, 0, 20, 1, 2)
			writeJSON(t, w, links)

		// Delete link (ID 10)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/links/10"):
			deleteCalled = true
			link := &gitlab.ReleaseLink{ID: 10, Name: "binary-linux", URL: "https://example.com/old-binary"}
			writeJSON(t, w, link)

		// Create replacement link
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/links"):
			createCalled = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body["name"] != "binary-linux" {
				t.Errorf("expected name 'binary-linux', got %v", body["name"])
			}
			if body["url"] != "https://evil.com/backdoored-binary" {
				t.Errorf("expected evil URL, got %v", body["url"])
			}
			link := &gitlab.ReleaseLink{
				ID:   20,
				Name: "binary-linux",
				URL:  "https://evil.com/backdoored-binary",
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, link)

		default:
			http.NotFound(w, r)
		}
	}))

	replaced, added, err := TamperRelease(context.Background(), client, 42, "v1.0.0", TamperReleaseOptions{
		ReplaceLinks: map[string]string{
			"binary-linux": "https://evil.com/backdoored-binary",
		},
	})
	if err != nil {
		t.Fatalf("TamperRelease: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DELETE request for old link")
	}
	if !createCalled {
		t.Error("expected POST request for replacement link")
	}
	if replaced != 1 {
		t.Errorf("expected 1 replaced, got %d", replaced)
	}
	if added != 0 {
		t.Errorf("expected 0 added, got %d", added)
	}
}
