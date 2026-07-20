package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestEnsureBranchDeconflict_ForceReusesExistingBranch(t *testing.T) {
	deleteCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled = true
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "main"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := gitlabx.New(server.URL, testTok)
	if err != nil {
		t.Fatalf("gitlabx.New() error = %v", err)
	}
	got, err := ensureBranchDeconflict(context.Background(), client, testProject, "main", "force", "", "")
	if err != nil {
		t.Fatalf("ensureBranchDeconflict() error = %v", err)
	}
	if got != "main" {
		t.Fatalf("branch = %q, want main", got)
	}
	if deleteCalled {
		t.Fatal("force strategy deleted the existing branch")
	}
}
