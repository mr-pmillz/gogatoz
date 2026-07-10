package bloodhound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientUploadSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v2/extensions" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &BearerAuth{Token: "test"})
	if err := c.UploadSchema(context.Background()); err != nil {
		t.Fatalf("UploadSchema: %v", err)
	}
}

func TestClientUploadData(t *testing.T) {
	var (
		startCalled  bool
		uploadCalled bool
		endCalled    bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			startCalled = true
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": 42}})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/42":
			uploadCalled = true
			if ct := r.Header.Get("Content-Type"); ct != "application/zip" {
				t.Errorf("Content-Type = %q, want application/zip", ct)
			}
			w.WriteHeader(http.StatusAccepted)

		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/42/end":
			endCalled = true
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Create a temporary ZIP file
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")
	if err := os.WriteFile(zipPath, []byte("PK fake zip"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewClient(srv.URL, &BearerAuth{Token: "test"})
	if err := c.UploadData(context.Background(), zipPath); err != nil {
		t.Fatalf("UploadData: %v", err)
	}

	if !startCalled {
		t.Error("start upload not called")
	}
	if !uploadCalled {
		t.Error("file upload not called")
	}
	if !endCalled {
		t.Error("end upload not called")
	}
}

func TestClientRunCypher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/graphs/cypher" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["query"] != "MATCH (n) RETURN n LIMIT 1" {
			t.Errorf("unexpected query: %v", body["query"])
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"nodes": map[string]any{},
				"edges": []any{},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &BearerAuth{Token: "test"})
	result, err := c.RunCypher(context.Background(), "MATCH (n) RETURN n LIMIT 1")
	if err != nil {
		t.Fatalf("RunCypher: %v", err)
	}
	if result["data"] == nil {
		t.Error("expected data in response")
	}
}

func TestClientCreateSavedQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			var sq SavedQuery
			json.NewDecoder(r.Body).Decode(&sq)
			if sq.Name != "Test Query" {
				t.Errorf("name = %q, want 'Test Query'", sq.Name)
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": 1}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &BearerAuth{Token: "test"})
	err := c.CreateSavedQuery(context.Background(), SavedQuery{
		Name:        "Test Query",
		Query:       "MATCH (n) RETURN n",
		Description: "A test query",
	})
	if err != nil {
		t.Fatalf("CreateSavedQuery: %v", err)
	}
}

func TestClientRetryOn5xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &BearerAuth{Token: "test"})
	c.RetryDelay = 1 * time.Millisecond // speed up test

	if err := c.UploadSchema(context.Background()); err != nil {
		t.Fatalf("UploadSchema after retries: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}
