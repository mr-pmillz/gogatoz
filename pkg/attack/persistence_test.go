package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// --- parseAccessLevel -------------------------------------------------------

func TestParseAccessLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    gitlab.AccessLevelValue
		wantErr bool
	}{
		{"guest", gitlab.GuestPermissions, false},
		{"reporter", gitlab.ReporterPermissions, false},
		{"developer", gitlab.DeveloperPermissions, false},
		{"maintainer", gitlab.MaintainerPermissions, false},
		{"maintain", gitlab.MaintainerPermissions, false},
		{"owner", gitlab.OwnerPermissions, false},
		{"", gitlab.DeveloperPermissions, false},
		{"DEVELOPER", gitlab.DeveloperPermissions, false},
		{"  Maintainer  ", gitlab.MaintainerPermissions, false},
		{"unknown", gitlab.DeveloperPermissions, true},
		{"admin", gitlab.DeveloperPermissions, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			got, err := parseAccessLevel(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseAccessLevel(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// --- GenerateMRPwnCI --------------------------------------------------------

func TestGenerateMRPwnCI(t *testing.T) {
	tests := []struct {
		name         string
		jobName      string
		runnerTags   []string
		downloadPath string
		wantContains []string
	}{
		{
			name:         "defaults",
			jobName:      "",
			runnerTags:   nil,
			downloadPath: "",
			wantContains: []string{"pwn-request:", "merge_request_event", "stages:", "CMD"},
		},
		{
			name:         "custom job and tags",
			jobName:      "my-pwn",
			runnerTags:   []string{"self-hosted", "linux"},
			downloadPath: "",
			wantContains: []string{"my-pwn:", `"self-hosted"`, `"linux"`, "tags:"},
		},
		{
			name:         "with artifacts path",
			jobName:      "grab-it",
			runnerTags:   nil,
			downloadPath: "/tmp/loot",
			wantContains: []string{"grab-it:", "artifacts:", "/tmp/loot", "expire_in"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
			p := NewPersistence(att)
			yaml := p.GenerateMRPwnCI(tt.jobName, tt.runnerTags, tt.downloadPath)
			for _, s := range tt.wantContains {
				if !strings.Contains(yaml, s) {
					t.Errorf("expected %q in output:\n%s", s, yaml)
				}
			}
			// Validate as parseable YAML
			doc, err := pipeline.Parse(strings.NewReader(yaml))
			if err != nil {
				t.Fatalf("generated YAML did not parse: %v\n---\n%s\n---", err, yaml)
			}
			if len(doc.Jobs) == 0 {
				t.Fatal("expected at least one job in parsed document")
			}
		})
	}
}

// --- RunMRPwn ---------------------------------------------------------------

func TestRunMRPwn(t *testing.T) {
	mux := http.NewServeMux()

	// GET /api/v4/user
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":       1,
			"username": "testbot",
			"name":     "Test Bot",
			"email":    "bot@example.com",
		})
	})

	// GET /api/v4/projects/1/repository/branches/gogatoz-attack — branch exists
	mux.HandleFunc("/api/v4/projects/1/repository/branches/gogatoz-attack", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "gogatoz-attack"})
	})

	// PUT /api/v4/projects/1/repository/files/.gitlab-ci.yml
	mux.HandleFunc("/api/v4/projects/1/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"file_path": ".gitlab-ci.yml"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// GET /api/v4/projects/1
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                  1,
			"default_branch":      "main",
			"path_with_namespace": "group/project",
		})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	url, err := p.RunMRPwn(context.Background(), "1", "", "pwn-test", nil, "")
	if err != nil {
		t.Fatalf("RunMRPwn: %v", err)
	}
	if !strings.Contains(url, "group/project") {
		t.Fatalf("expected pipeline URL containing project path, got %s", url)
	}
	if !strings.Contains(url, "gogatoz-attack") {
		t.Fatalf("expected pipeline URL containing branch ref, got %s", url)
	}
}

// --- CreateDeployKey --------------------------------------------------------

func TestCreateDeployKey(t *testing.T) {
	mux := http.NewServeMux()

	// POST /api/v4/projects/1/deploy_keys
	mux.HandleFunc("/api/v4/projects/1/deploy_keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": int64(99), "title": "test"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "deploy_key.pem")

	id, pubKey, err := p.CreateDeployKey(context.Background(), "1", "test", keyPath)
	if err != nil {
		t.Fatalf("CreateDeployKey: %v", err)
	}
	if id != 99 {
		t.Fatalf("expected deploy key id=99, got %d", id)
	}
	if pubKey == "" {
		t.Fatal("expected non-empty public key string")
	}
	if !strings.HasPrefix(pubKey, "ssh-rsa ") {
		t.Fatalf("expected ssh-rsa prefix, got %q", pubKey[:20])
	}

	// Verify PEM file exists and contains private key
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read private key file: %v", err)
	}
	if !strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("expected PEM-encoded private key in file")
	}
}

func TestCreateDeployKey_EmptyPath(t *testing.T) {
	att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
	p := NewPersistence(att)

	_, _, err := p.CreateDeployKey(context.Background(), "1", "test", "")
	if err == nil {
		t.Fatal("expected error for empty keyPath")
	}
	if !strings.Contains(err.Error(), "keyPath is required") {
		t.Fatalf("expected keyPath error, got: %v", err)
	}
}

// --- AddProjectMemberByUsername ---------------------------------------------

func TestAddProjectMemberByUsername(t *testing.T) {
	mux := http.NewServeMux()

	// GET /api/v4/users?username=alice
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		username := r.URL.Query().Get("username")
		if username == "alice" {
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": int64(42), "username": "alice", "name": "Alice"},
			})
			return
		}
		// No user found
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})

	// POST /api/v4/projects/1/members
	mux.HandleFunc("/api/v4/projects/1/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":           int64(42),
				"username":     "alice",
				"access_level": 30,
			})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)

	// Successful add
	err := p.AddProjectMemberByUsername(context.Background(), "1", "alice", "developer")
	if err != nil {
		t.Fatalf("AddProjectMemberByUsername: %v", err)
	}
}

func TestAddProjectMemberByUsername_EmptyUsername(t *testing.T) {
	att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
	p := NewPersistence(att)

	err := p.AddProjectMemberByUsername(context.Background(), "1", "", "developer")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
	if !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("expected 'username is required' error, got: %v", err)
	}
}

func TestAddProjectMemberByUsername_UserNotFound(t *testing.T) {
	mux := http.NewServeMux()

	// GET /api/v4/users?username=nobody returns empty array
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	err := p.AddProjectMemberByUsername(context.Background(), "1", "nobody", "developer")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected 'user not found' error, got: %v", err)
	}
}

func TestAddProjectMemberByUsername_InvalidAccessLevel(t *testing.T) {
	att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
	p := NewPersistence(att)

	err := p.AddProjectMemberByUsername(context.Background(), "1", "alice", "superadmin")
	if err == nil {
		t.Fatal("expected error for invalid access level")
	}
	if !strings.Contains(err.Error(), "unknown access level") {
		t.Fatalf("expected 'unknown access level' error, got: %v", err)
	}
}

// --- CheckApprovalRules -----------------------------------------------------

func TestCheckApprovalRules_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/merge_requests/10/approvals", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":                 10,
			"iid":                10,
			"approvals_required": 1,
			"approvals_left":     0,
			"approved":           true,
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	status, err := p.CheckApprovalRules(context.Background(), "1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ApprovalsRequired != 1 {
		t.Fatalf("expected 1 required approval, got %d", status.ApprovalsRequired)
	}
	if !status.Approved {
		t.Fatal("expected approved=true")
	}
}

// --- ApproveMergeRequest ----------------------------------------------------

func TestApproveMergeRequest_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/merge_requests/10/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 10, "approved": true})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	err := p.ApproveMergeRequest(context.Background(), "1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- MergeMergeRequest ------------------------------------------------------

func TestMergeMergeRequest_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/merge_requests/10/merge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":    10,
			"iid":   10,
			"state": "merged",
		})
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	err := p.MergeMergeRequest(context.Background(), "1", 10, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- RunAutoMerge -----------------------------------------------------------

func TestRunAutoMerge_FullChain(t *testing.T) {
	mux := http.NewServeMux()

	// SetupUser
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": 1, "username": "attacker", "name": "Attacker", "email": "a@a.com",
		})
	})
	// EnsureBranch: branch doesn't exist
	mux.HandleFunc("/api/v4/projects/1/repository/branches/attack-br", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// GetProject
	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": 1, "default_branch": "main", "path_with_namespace": "group/project",
		})
	})
	// CreateBranch
	mux.HandleFunc("/api/v4/projects/1/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"name": "attack-br"})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// UpsertFile
	mux.HandleFunc("/api/v4/projects/1/repository/files/README.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound) // fall through to create
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"file_path": "README.md"})
			return
		}
	})
	// CreateMergeRequest
	mux.HandleFunc("/api/v4/projects/1/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"iid": int64(5), "web_url": "https://gitlab.com/group/project/-/merge_requests/5",
			})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// GetConfiguration (approvals)
	mux.HandleFunc("/api/v4/projects/1/merge_requests/5/approvals", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"approvals_required": 0, "approvals_left": 0, "approved": true,
		})
	})
	// ApproveMergeRequest
	mux.HandleFunc("/api/v4/projects/1/merge_requests/5/approve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 5, "approved": true})
	})
	// AcceptMergeRequest (merge)
	mux.HandleFunc("/api/v4/projects/1/merge_requests/5/merge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 5, "state": "merged"})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	p := NewPersistence(att)
	result, err := p.RunAutoMerge(context.Background(), "1",
		"attack-br", "README.md", "# pwned", "supply chain commit",
		"Update README", "", "")
	if err != nil {
		t.Fatalf("RunAutoMerge: %v", err)
	}
	if result.MRIID != 5 {
		t.Fatalf("expected MR IID=5, got %d", result.MRIID)
	}
	if !result.Approved {
		t.Fatal("expected approved=true")
	}
	if !result.Merged {
		t.Fatal("expected merged=true")
	}
	if result.ApproveErr != "" {
		t.Fatalf("unexpected approve error: %s", result.ApproveErr)
	}
	if result.MergeErr != "" {
		t.Fatalf("unexpected merge error: %s", result.MergeErr)
	}
}

func TestCreateDeployKey_DoesNotOverwriteExistingFile(t *testing.T) {
	att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
	p := NewPersistence(att)
	keyPath := filepath.Join(t.TempDir(), "existing.pem")
	if err := os.WriteFile(keyPath, []byte("keep-me"), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, _, err := p.CreateDeployKey(context.Background(), "1", "test", keyPath)
	if err == nil {
		t.Fatal("expected existing key path to be rejected")
	}
	data, readErr := os.ReadFile(keyPath)
	if readErr != nil || string(data) != "keep-me" {
		t.Fatalf("existing file changed: data=%q err=%v", data, readErr)
	}
}

func TestCreateDeployKey_RemovesFileWhenAPIRegistrationFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/deploy_keys", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"registration failed"}`))
	})
	att, ts := newMockAttacker(t, mux)
	defer ts.Close()
	keyPath := filepath.Join(t.TempDir(), "deploy.pem")

	_, _, err := NewPersistence(att).CreateDeployKey(context.Background(), "1", "test", keyPath)
	if err == nil {
		t.Fatal("expected deploy key registration failure")
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("orphan private key remained after failure: %v", statErr)
	}
}
