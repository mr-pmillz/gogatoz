package tamper

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const testEntrypoint = "entrypoint.sh"

// tagMockState tracks API calls during tag tampering for verification.
type tagMockState struct {
	getTagCalled       bool
	getCommitCalled    bool
	getProjectCalled   bool
	createBranchCalled bool
	createCommitCalled bool
	deleteTagCalled    bool
	createTagCalled    bool
	deleteBranchCalled bool

	// Captured values for assertions
	commitAuthorName  string
	commitAuthorEmail string
	commitMessage     string
	commitFilePath    string
	commitFileContent string
	createTagRef      string
}

func newTagMockHandler(t *testing.T, state *tagMockState) http.Handler {
	t.Helper()
	now := time.Now()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /api/v4/projects/:id/repository/tags/:tag
		case r.Method == http.MethodGet && strings.Contains(path, "/repository/tags/"):
			state.getTagCalled = true
			tag := &gitlab.Tag{
				Name: "v1.0.0",
				Commit: &gitlab.Commit{
					ID: "abc123def456",
				},
			}
			writeJSON(t, w, tag)

		// GET /api/v4/projects/:id/repository/commits/:sha
		case r.Method == http.MethodGet && strings.Contains(path, "/repository/commits/"):
			state.getCommitCalled = true
			commit := &gitlab.Commit{
				ID:             "abc123def456",
				AuthorName:     "Original Author",
				AuthorEmail:    "author@original.com",
				CommitterName:  "Original Committer",
				CommitterEmail: "committer@original.com",
				Message:        "Merge PR #481: Add new feature\n\nFixes #123",
				AuthoredDate:   &now,
				CommittedDate:  &now,
			}
			writeJSON(t, w, commit)

		// GET /api/v4/projects/:id
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/api/v4/projects/42"):
			state.getProjectCalled = true
			project := map[string]any{
				"id":             42,
				"default_branch": "main",
			}
			writeJSON(t, w, project)

		// POST /api/v4/projects/:id/repository/branches
		case r.Method == http.MethodPost && strings.Contains(path, "/repository/branches"):
			state.createBranchCalled = true
			branch := map[string]any{
				"name": "_gzx-tag-tmp-test",
				"commit": map[string]any{
					"id": "abc123def456",
				},
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, branch)

		// POST /api/v4/projects/:id/repository/commits
		case r.Method == http.MethodPost && strings.Contains(path, "/repository/commits"):
			state.createCommitCalled = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode commit body: %v", err)
			}
			state.commitAuthorName, _ = body["author_name"].(string)
			state.commitAuthorEmail, _ = body["author_email"].(string)
			state.commitMessage, _ = body["commit_message"].(string)

			if actions, ok := body["actions"].([]any); ok && len(actions) > 0 {
				action, _ := actions[0].(map[string]any)
				state.commitFilePath, _ = action["file_path"].(string)
				state.commitFileContent, _ = action["content"].(string)
			}

			commit := &gitlab.Commit{
				ID:          "new789commit",
				AuthorName:  state.commitAuthorName,
				AuthorEmail: state.commitAuthorEmail,
				Message:     state.commitMessage,
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, commit)

		// DELETE /api/v4/projects/:id/repository/tags/:tag
		case r.Method == http.MethodDelete && strings.Contains(path, "/repository/tags/"):
			state.deleteTagCalled = true
			w.WriteHeader(http.StatusNoContent)

		// POST /api/v4/projects/:id/repository/tags (create new tag)
		case r.Method == http.MethodPost && strings.Contains(path, "/repository/tags"):
			state.createTagCalled = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create tag body: %v", err)
			}
			state.createTagRef, _ = body["ref"].(string)

			tag := &gitlab.Tag{
				Name: "v1.0.0",
				Commit: &gitlab.Commit{
					ID: "new789commit",
				},
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, tag)

		// DELETE /api/v4/projects/:id/repository/branches/:branch (cleanup)
		case r.Method == http.MethodDelete && strings.Contains(path, "/repository/branches/"):
			state.deleteBranchCalled = true
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Logf("unhandled request: %s %s", r.Method, path)
			http.NotFound(w, r)
		}
	})
}

func TestTamperTag_Success(t *testing.T) {
	state := &tagMockState{}
	client := testClient(t, newTagMockHandler(t, state))

	result, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		TagName:        "v1.0.0",
		TargetFile:     testEntrypoint,
		PayloadContent: "#!/bin/sh\necho pwned",
	})
	if err != nil {
		t.Fatalf("TamperTag: %v", err)
	}

	// Verify all API calls made
	if !state.getTagCalled {
		t.Error("expected GetTag call")
	}
	if !state.getCommitCalled {
		t.Error("expected GetCommit call")
	}
	if !state.getProjectCalled {
		t.Error("expected GetProject call (for default branch)")
	}
	if !state.createBranchCalled {
		t.Error("expected CreateBranch call")
	}
	if !state.createCommitCalled {
		t.Error("expected CreateCommit call")
	}
	if !state.deleteTagCalled {
		t.Error("expected DeleteTag call")
	}
	if !state.createTagCalled {
		t.Error("expected CreateTag call")
	}
	if !state.deleteBranchCalled {
		t.Error("expected DeleteBranch call (cleanup)")
	}

	// Verify metadata cloning
	if state.commitAuthorName != "Original Author" {
		t.Errorf("expected cloned author name 'Original Author', got %q", state.commitAuthorName)
	}
	if state.commitAuthorEmail != "author@original.com" {
		t.Errorf("expected cloned email 'author@original.com', got %q", state.commitAuthorEmail)
	}
	if !strings.Contains(state.commitMessage, "Merge PR #481") {
		t.Errorf("expected cloned commit message with PR reference, got %q", state.commitMessage)
	}

	// Verify file swap
	if state.commitFilePath != testEntrypoint {
		t.Errorf("expected file path 'entrypoint.sh', got %q", state.commitFilePath)
	}
	if !strings.Contains(state.commitFileContent, "echo pwned") {
		t.Errorf("expected payload content in commit, got %q", state.commitFileContent)
	}

	// Verify new tag points to new commit
	if state.createTagRef != "new789commit" {
		t.Errorf("expected new tag to point to 'new789commit', got %q", state.createTagRef)
	}

	// Verify result
	if result.TagName != "v1.0.0" {
		t.Errorf("expected tag name 'v1.0.0', got %q", result.TagName)
	}
	if result.OriginalCommitSHA != "abc123def456" {
		t.Errorf("expected original SHA 'abc123def456', got %q", result.OriginalCommitSHA)
	}
	if result.NewCommitSHA != "new789commit" {
		t.Errorf("expected new SHA 'new789commit', got %q", result.NewCommitSHA)
	}
	if result.SourceRef != "main" {
		t.Errorf("expected source ref 'main', got %q", result.SourceRef)
	}
	if result.TargetFile != testEntrypoint {
		t.Errorf("expected target file 'entrypoint.sh', got %q", result.TargetFile)
	}
	if !strings.Contains(result.ClonedAuthor, "Original Author") {
		t.Errorf("expected cloned author info, got %q", result.ClonedAuthor)
	}
}

func TestTamperTag_MissingTagName(t *testing.T) {
	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no API calls expected")
	}))

	_, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		PayloadContent: "#!/bin/sh\necho pwned",
	})
	if err == nil {
		t.Fatal("expected error for missing tag name")
	}
	if !strings.Contains(err.Error(), "tag name is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTamperTag_MissingPayload(t *testing.T) {
	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no API calls expected")
	}))

	_, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		TagName: "v1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for missing payload")
	}
	if !strings.Contains(err.Error(), "payload content is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTamperTag_TagNotFound(t *testing.T) {
	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repository/tags/") {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(t, w, map[string]string{"error": "404 Tag Not Found"})
			return
		}
		http.NotFound(w, r)
	}))

	_, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		TagName:        "v999.0.0",
		PayloadContent: "#!/bin/sh\necho pwned",
	})
	if err == nil {
		t.Fatal("expected error for missing tag")
	}
	if !strings.Contains(err.Error(), "get tag") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTamperTag_CustomSourceRef(t *testing.T) {
	state := &tagMockState{}
	client := testClient(t, newTagMockHandler(t, state))

	result, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		TagName:        "v1.0.0",
		TargetFile:     testEntrypoint,
		PayloadContent: "#!/bin/sh\necho pwned",
		SourceRef:      "develop",
	})
	if err != nil {
		t.Fatalf("TamperTag: %v", err)
	}

	// Should NOT call GetProject when SourceRef is explicit
	if state.getProjectCalled {
		t.Error("expected GetProject NOT to be called when SourceRef is explicit")
	}
	if result.SourceRef != "develop" {
		t.Errorf("expected source ref 'develop', got %q", result.SourceRef)
	}
}

func TestTamperTag_AuthorOverride(t *testing.T) {
	state := &tagMockState{}
	client := testClient(t, newTagMockHandler(t, state))

	_, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		TagName:        "v1.0.0",
		TargetFile:     testEntrypoint,
		PayloadContent: "#!/bin/sh\necho pwned",
		AuthorName:     "Custom Author",
		AuthorEmail:    "custom@override.com",
		CommitMessage:  "chore: custom message",
	})
	if err != nil {
		t.Fatalf("TamperTag: %v", err)
	}

	if state.commitAuthorName != "Custom Author" {
		t.Errorf("expected overridden author name 'Custom Author', got %q", state.commitAuthorName)
	}
	if state.commitAuthorEmail != "custom@override.com" {
		t.Errorf("expected overridden email 'custom@override.com', got %q", state.commitAuthorEmail)
	}
	if state.commitMessage != "chore: custom message" {
		t.Errorf("expected overridden commit message, got %q", state.commitMessage)
	}
}

func TestTamperTag_DefaultTargetFile(t *testing.T) {
	state := &tagMockState{}
	client := testClient(t, newTagMockHandler(t, state))

	result, err := TamperTag(context.Background(), client, 42, TamperTagOptions{
		TagName:        "v1.0.0",
		PayloadContent: "#!/bin/sh\necho pwned",
	})
	if err != nil {
		t.Fatalf("TamperTag: %v", err)
	}

	if state.commitFilePath != testEntrypoint {
		t.Errorf("expected default target file 'entrypoint.sh', got %q", state.commitFilePath)
	}
	if result.TargetFile != testEntrypoint {
		t.Errorf("expected result target file 'entrypoint.sh', got %q", result.TargetFile)
	}
}

func TestGetTagCommit_Success(t *testing.T) {
	now := time.Now()
	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repository/tags/"):
			tag := &gitlab.Tag{
				Name: "v1.0.0",
				Commit: &gitlab.Commit{
					ID: "sha123",
				},
			}
			writeJSON(t, w, tag)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repository/commits/"):
			commit := &gitlab.Commit{
				ID:             "sha123",
				AuthorName:     "Test Author",
				AuthorEmail:    "test@example.com",
				CommitterName:  "Test Committer",
				CommitterEmail: "committer@example.com",
				Message:        "test commit message",
				AuthoredDate:   &now,
				CommittedDate:  &now,
			}
			writeJSON(t, w, commit)
		default:
			http.NotFound(w, r)
		}
	}))

	info, err := GetTagCommit(context.Background(), client, 42, "v1.0.0")
	if err != nil {
		t.Fatalf("GetTagCommit: %v", err)
	}
	if info.SHA != "sha123" {
		t.Errorf("expected SHA 'sha123', got %q", info.SHA)
	}
	if info.AuthorName != "Test Author" {
		t.Errorf("expected author 'Test Author', got %q", info.AuthorName)
	}
	if info.Message != "test commit message" {
		t.Errorf("expected message 'test commit message', got %q", info.Message)
	}
}
