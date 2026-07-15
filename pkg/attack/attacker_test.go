package attack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestNewAttacker(t *testing.T) {
	att := NewAttacker(nil, "https://gitlab.com", "Test User", "test@example.com", 0)
	if att == nil {
		t.Fatal("NewAttacker returned nil")
		return
	}
	if att.GitLabURL != "https://gitlab.com" {
		t.Errorf("expected GitLabURL=https://gitlab.com, got %s", att.GitLabURL)
	}
	if att.AuthorName != "Test User" {
		t.Errorf("expected AuthorName=Test User, got %s", att.AuthorName)
	}
	if att.AuthorEmail != "test@example.com" {
		t.Errorf("expected AuthorEmail=test@example.com, got %s", att.AuthorEmail)
	}
}

// newMockAttacker creates an Attacker backed by a mock GitLab API server.
// The returned mux can be extended with additional handlers.
// Caller must defer ts.Close().
func newMockAttacker(t *testing.T, mux *http.ServeMux) (*Attacker, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(mux)
	cl, err := gitlabx.New(ts.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	att := NewAttacker(cl, ts.URL, "Test User", "test@example.com", 0)
	return att, ts
}

// --- EraseJob ---------------------------------------------------------------

func TestEraseJob_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/jobs/42/erase", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 42})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.EraseJob(context.Background(), "1", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEraseJob_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/jobs/999/erase", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "404 Job Not Found"})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.EraseJob(context.Background(), "1", 999)
	if err == nil {
		t.Fatal("expected error for non-existent job")
	}
}

// --- DeletePipeline ---------------------------------------------------------

func TestDeletePipeline_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipelines/10", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.DeletePipeline(context.Background(), "1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- EraseRecentPipelines ---------------------------------------------------

func TestEraseRecentPipelines_ErasesJobsAndDeletes(t *testing.T) {
	var erasedJobs []string
	var deletedPipelines []string
	mux := http.NewServeMux()
	// List pipelines for ref
	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "5")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "1")
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 100, "ref": "attack", "status": "success"},
		})
	})
	// List jobs for pipeline 100
	mux.HandleFunc("/api/v4/projects/1/pipelines/100/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "100")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "2")
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 200, "name": "job1", "status": "success"},
			{"id": 201, "name": "job2", "status": "success"},
		})
	})
	// Erase job endpoints
	mux.HandleFunc("/api/v4/projects/1/jobs/200/erase", func(w http.ResponseWriter, r *http.Request) {
		erasedJobs = append(erasedJobs, "200")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 200})
	})
	mux.HandleFunc("/api/v4/projects/1/jobs/201/erase", func(w http.ResponseWriter, r *http.Request) {
		erasedJobs = append(erasedJobs, "201")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 201})
	})
	// Delete pipeline endpoint
	mux.HandleFunc("/api/v4/projects/1/pipelines/100", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedPipelines = append(deletedPipelines, "100")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	count, err := att.EraseRecentPipelines(context.Background(), "1", "attack", 5, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 pipeline processed, got %d", count)
	}
	if len(erasedJobs) != 2 {
		t.Fatalf("expected 2 jobs erased, got %d", len(erasedJobs))
	}
	if len(deletedPipelines) != 1 {
		t.Fatalf("expected 1 pipeline deleted, got %d", len(deletedPipelines))
	}
}

func TestEraseRecentPipelines_EraseOnlyNoDelete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "5")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "1")
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 50, "ref": "main", "status": "success"},
		})
	})
	mux.HandleFunc("/api/v4/projects/1/pipelines/50/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "100")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "0")
		json.NewEncoder(w).Encode([]map[string]any{})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	count, err := att.EraseRecentPipelines(context.Background(), "1", "", 5, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 pipeline processed, got %d", count)
	}
}

// --- TriggerPipeline --------------------------------------------------------

func TestTriggerPipeline_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipeline", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":      55,
			"web_url": "https://gitlab.com/group/project/-/pipelines/55",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	id, url, err := att.TriggerPipeline(context.Background(), "1", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 55 {
		t.Fatalf("expected pipeline ID=55, got %d", id)
	}
	if !strings.Contains(url, "55") {
		t.Fatalf("expected URL to contain pipeline ID, got %s", url)
	}
}

// --- GetFileContent ---------------------------------------------------------

func TestGetFileContent_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/scripts%2Fbuild.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"file_name": "build.sh",
			"file_path": "scripts/build.sh",
			"content":   "IyEvYmluL2Jhc2gKZWNobyBoZWxsbw==",
			"encoding":  "base64",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	content, err := att.GetFileContent(context.Background(), "1", "main", "scripts/build.sh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content == "" {
		t.Fatal("expected non-empty content")
	}
}

func TestGetFileContent_StripsLeadingSlash(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/file.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"file_name": "file.txt",
			"content":   "dGVzdA==",
			"encoding":  "base64",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	_, err := att.GetFileContent(context.Background(), "1", "main", "/file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- BranchExists -----------------------------------------------------------

func TestBranchExists_True(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches/main", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"name": "main"})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	exists, err := att.BranchExists(context.Background(), "1", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Fatal("expected branch to exist")
	}
}

func TestBranchExists_False(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches/nope", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "404 Branch Not Found"})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	exists, err := att.BranchExists(context.Background(), "1", "nope")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Fatal("expected branch not to exist")
	}
}

func TestBranchExists_EmptyBranch(t *testing.T) {
	mux := http.NewServeMux()
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	_, err := att.BranchExists(context.Background(), "1", "")
	if err == nil {
		t.Fatal("expected error for empty branch")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' in error, got %v", err)
	}
}

// --- DeleteBranch -----------------------------------------------------------

func TestDeleteBranch_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches/feat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.DeleteBranch(context.Background(), "1", "feat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- EnsureBranch -----------------------------------------------------------

func TestEnsureBranch_AlreadyExists(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/branches/feat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"name": "feat"})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.EnsureBranch(context.Background(), "1", "feat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureBranch_Creates(t *testing.T) {
	var createCalled bool
	mux := http.NewServeMux()
	// GetBranch returns 404
	mux.HandleFunc("/api/v4/projects/1/repository/branches/new-branch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404 Branch Not Found"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// GetProject returns project with default branch
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":             1,
			"default_branch": "main",
		})
	})
	// CreateBranch
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			createCalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"name": "new-branch"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.EnsureBranch(context.Background(), "1", "new-branch")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !createCalled {
		t.Fatal("expected CreateBranch to be called")
	}
}

// --- UpsertFile -------------------------------------------------------------

func TestUpsertFile_UpdateSucceeds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/ci.yml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"file_path": "ci.yml"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.UpsertFile(context.Background(), "1", "main", "ci.yml", "content", "msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpsertFile_FallbackToCreate(t *testing.T) {
	var createCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/new.yml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			// UpdateFile returns 404 — file does not exist yet
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
			return
		}
		if r.Method == http.MethodPost {
			createCalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"file_path": "new.yml"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.UpsertFile(context.Background(), "1", "main", "new.yml", "content", "msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !createCalled {
		t.Fatal("expected CreateFile to be called as fallback")
	}
}

func TestUpsertFile_DualFailure_JoinsErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/fail.yml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": "500 Internal Server Error"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.UpsertFile(context.Background(), "1", "main", "fail.yml", "content", "msg")
	if err == nil {
		t.Fatal("expected error when both update and create fail")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "upsert fail.yml") {
		t.Errorf("expected 'upsert fail.yml' in error, got: %s", errStr)
	}
	if !strings.Contains(errStr, "404") || !strings.Contains(errStr, "500") {
		t.Errorf("expected both status codes in joined error, got: %s", errStr)
	}
}

// --- SetupUser --------------------------------------------------------------

func TestSetupUser_FillsAuthor(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":       42,
			"username": "testbot",
			"name":     "Test Bot",
			"email":    "bot@example.com",
		})
	})

	// Create attacker with empty author fields so SetupUser fills them
	ts := httptest.NewServer(mux)
	defer ts.Close()
	cl, err := gitlabx.New(ts.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	att := NewAttacker(cl, ts.URL, "", "", 0)

	u, err := att.SetupUser(context.Background())
	if err != nil {
		t.Fatalf("SetupUser: %v", err)
	}
	if u == nil {
		t.Fatal("expected non-nil user")
		return
	}
	if u.Username != "testbot" {
		t.Fatalf("expected username=testbot, got %s", u.Username)
	}
	if att.AuthorName != "Test Bot" {
		t.Fatalf("expected AuthorName=Test Bot, got %s", att.AuthorName)
	}
}

// --- CreateSnippet ----------------------------------------------------------

func TestCreateSnippet_Public(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/snippets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":         99,
			"title":      "test-snippet",
			"visibility": "public",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	snip, resp, err := att.CreateSnippet(context.Background(), "test-snippet", "data.txt", "secret data", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if snip == nil {
		t.Fatal("expected non-nil snippet")
		return
	}
	if snip.ID != 99 {
		t.Fatalf("expected snippet ID=99, got %d", snip.ID)
	}
}

func TestCreateSnippet_Private(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/snippets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":         100,
			"title":      "private-snippet",
			"visibility": "private",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	snip, _, err := att.CreateSnippet(context.Background(), "private-snippet", "data.txt", "secret", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snip.ID != 100 {
		t.Fatalf("expected snippet ID=100, got %d", snip.ID)
	}
}

// --- CreateMergeRequest -----------------------------------------------------

func TestCreateMergeRequest_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"iid":     42,
			"web_url": "https://gitlab.com/group/project/-/merge_requests/42",
			"title":   "Test MR",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	mr, err := att.CreateMergeRequest(context.Background(), "1", "feat", "main", "Test MR", "desc body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mr == nil {
		t.Fatal("expected non-nil merge request")
		return
	}
	if mr.IID != 42 {
		t.Fatalf("expected IID=42, got %d", mr.IID)
	}
}

func TestCreateMergeRequest_EmptySourceBranch(t *testing.T) {
	mux := http.NewServeMux()
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	_, err := att.CreateMergeRequest(context.Background(), "1", "", "main", "title", "desc")
	if err == nil {
		t.Fatal("expected error for empty source branch")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' in error, got %v", err)
	}
}

func TestCreateMergeRequest_ResolvesDefaultBranch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":             1,
			"default_branch": "develop",
		})
	})
	mux.HandleFunc("/api/v4/projects/1/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"iid":     1,
			"web_url": "https://gitlab.com/group/project/-/merge_requests/1",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	mr, err := att.CreateMergeRequest(context.Background(), "1", "feat", "", "title", "desc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mr == nil {
		t.Fatal("expected non-nil merge request")
	}
}

// --- CommitCIPipeline -------------------------------------------------------

func TestCommitCIPipeline_Success(t *testing.T) {
	mux := http.NewServeMux()
	// GetBranch returns 404 (branch does not exist yet)
	mux.HandleFunc("/api/v4/projects/1/repository/branches/attack-branch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404 Branch Not Found"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// GetProject (for EnsureBranch default branch lookup, and for CommitCIPipeline final URL)
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":                  1,
			"default_branch":      "main",
			"path_with_namespace": "group/project",
		})
	})
	// CreateBranch
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"name": "attack-branch"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// UpsertFile — UpdateFile returns 404, CreateFile succeeds
	mux.HandleFunc("/api/v4/projects/1/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404 File Not Found"})
			return
		}
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"file_path": ".gitlab-ci.yml"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	pipelineURL, err := att.CommitCIPipeline(context.Background(), "1", "attack-branch", "image: alpine\nscript: echo hi", "test commit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(pipelineURL, "group/project") {
		t.Fatalf("expected URL to contain project path, got %s", pipelineURL)
	}
	if !strings.Contains(pipelineURL, "ref=attack-branch") {
		t.Fatalf("expected URL to contain branch ref, got %s", pipelineURL)
	}
}

// --- DeleteFile -------------------------------------------------------------

func TestDeleteFile_Success(t *testing.T) {
	mux := http.NewServeMux()
	// SDK URL-encodes file path slashes, so use a simple filename
	mux.HandleFunc("/api/v4/projects/1/repository/files/file.txt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.DeleteFile(context.Background(), "1", "main", "file.txt", "cleanup")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteFile_EmptyBranch(t *testing.T) {
	mux := http.NewServeMux()
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.DeleteFile(context.Background(), "1", "", "file.txt", "msg")
	if err == nil {
		t.Fatal("expected error for empty branch")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' in error, got %v", err)
	}
}

func TestDeleteFile_EmptyPath(t *testing.T) {
	mux := http.NewServeMux()
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.DeleteFile(context.Background(), "1", "main", "", "msg")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' in error, got %v", err)
	}
}

func TestDeleteFile_StripsLeadingSlash(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/repository/files/clean.txt", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.DeleteFile(context.Background(), "1", "main", "/clean.txt", "cleanup")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(gotPath, "//") {
		t.Fatalf("expected clean path without double slashes, got %s", gotPath)
	}
}

// --- RevokeDeployKey --------------------------------------------------------

func TestRevokeDeployKey_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/deploy_keys/42", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.RevokeDeployKey(context.Background(), "1", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- RemoveProjectMember ----------------------------------------------------

func TestRemoveProjectMember_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/members/99", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	err := att.RemoveProjectMember(context.Background(), "1", 99)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
