package enumerate

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

// newRepoMockServer creates a mock GitLab API server and client for repo.go tests.
// Caller must defer ts.Close().
func newRepoMockServer(t *testing.T, mux *http.ServeMux) (*gitlabx.Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(mux)
	cl, err := gitlabx.New(ts.URL, "tok")
	if err != nil {
		ts.Close()
		t.Fatalf("gitlabx.New: %v", err)
	}
	return cl, ts
}

// --- GetDefaultBranch -------------------------------------------------------

func TestGetDefaultBranch_NilClient(t *testing.T) {
	_, err := GetDefaultBranch(context.Background(), nil, "1")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected 'nil client' error, got: %v", err)
	}
}

func TestGetDefaultBranch_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             int64(1),
			"default_branch": "develop",
		})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	branch, err := GetDefaultBranch(context.Background(), cl, "1")
	if err != nil {
		t.Fatalf("GetDefaultBranch: %v", err)
	}
	if branch != "develop" {
		t.Fatalf("expected branch=develop, got %s", branch)
	}
}

func TestGetDefaultBranch_EmptyBranch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             int64(1),
			"default_branch": "",
		})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	branch, err := GetDefaultBranch(context.Background(), cl, "1")
	if err != nil {
		t.Fatalf("GetDefaultBranch: %v", err)
	}
	if branch != "" {
		t.Fatalf("expected empty branch, got %s", branch)
	}
}

func TestGetDefaultBranch_APIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/999", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 Project Not Found"})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	_, err := GetDefaultBranch(context.Background(), cl, "999")
	if err == nil {
		t.Fatal("expected error for API error")
	}
}

// --- FileExists -------------------------------------------------------------

func TestFileExists_NilClient(t *testing.T) {
	_, err := FileExists(context.Background(), nil, "1", "main", ".gitlab-ci.yml")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected 'nil client' error, got: %v", err)
	}
}

func TestFileExists_EmptyPath(t *testing.T) {
	mux := http.NewServeMux()
	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	_, err := FileExists(context.Background(), cl, "1", "main", "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("expected 'path is required' error, got: %v", err)
	}
}

func TestFileExists_Found(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"file_name": ".gitlab-ci.yml",
			"file_path": ".gitlab-ci.yml",
			"encoding":  "base64",
			"content":   "c3RhZ2VzOiBbYnVpbGRd",
		})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	exists, err := FileExists(context.Background(), cl, "1", "main", ".gitlab-ci.yml")
	if err != nil {
		t.Fatalf("FileExists: %v", err)
	}
	if !exists {
		t.Fatal("expected file to exist")
	}
}

func TestFileExists_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/missing.yml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	exists, err := FileExists(context.Background(), cl, "1", "main", "missing.yml")
	if err != nil {
		t.Fatalf("FileExists: %v", err)
	}
	if exists {
		t.Fatal("expected file not to exist")
	}
}

func TestFileExists_ServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/error.yml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	_, err := FileExists(context.Background(), cl, "1", "main", "error.yml")
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

// --- ListRefs ---------------------------------------------------------------

func TestListRefs_NilClient(t *testing.T) {
	_, err := ListRefs(context.Background(), nil, "1", 0)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected 'nil client' error, got: %v", err)
	}
}

func TestListRefs_SinglePage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "100")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "3")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "main", "default": true},
			{"name": "develop", "default": false},
			{"name": "feature/test", "default": false},
		})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	refs, err := ListRefs(context.Background(), cl, "1", 0)
	if err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d", len(refs))
	}
	expected := []string{"main", "develop", "feature/test"}
	for i, want := range expected {
		if refs[i] != want {
			t.Fatalf("refs[%d] = %q, want %q", i, refs[i], want)
		}
	}
}

func TestListRefs_WithLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "2")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "3")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "main", "default": true},
			{"name": "develop", "default": false},
			{"name": "extra", "default": false},
		})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	refs, err := ListRefs(context.Background(), cl, "1", 2)
	if err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs (limited), got %d: %v", len(refs), refs)
	}
}

func TestListRefs_Pagination(t *testing.T) {
	var requestCount int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		page := r.URL.Query().Get("page")
		if page == "" || page == "1" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "2")
			w.Header().Set("X-Per-Page", "2")
			w.Header().Set("X-Total-Pages", "2")
			w.Header().Set("X-Total", "3")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "main", "default": true},
				{"name": "develop", "default": false},
			})
			return
		}
		// Page 2
		w.Header().Set("X-Page", "2")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "2")
		w.Header().Set("X-Total-Pages", "2")
		w.Header().Set("X-Total", "3")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "feature/x", "default": false},
		})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	refs, err := ListRefs(context.Background(), cl, "1", 0)
	if err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs across 2 pages, got %d: %v", len(refs), refs)
	}
	if requestCount != 2 {
		t.Fatalf("expected 2 requests (pagination), got %d", requestCount)
	}
	expected := []string{"main", "develop", "feature/x"}
	for i, want := range expected {
		if refs[i] != want {
			t.Fatalf("refs[%d] = %q, want %q", i, refs[i], want)
		}
	}
}

func TestListRefs_APIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "403 Forbidden"})
	})

	cl, ts := newRepoMockServer(t, mux)
	defer ts.Close()

	_, err := ListRefs(context.Background(), cl, "1", 0)
	if err == nil {
		t.Fatal("expected error for API error")
	}
	_ = fmt.Sprintf("error: %v", err) // ensure error is printable
}
