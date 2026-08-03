package validate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestProbeToken_FullAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			json.NewEncoder(w).Encode(map[string]any{
				"id": 1, "name": "admin-token", "revoked": false, "active": true,
				"scopes":     []string{"api", "read_user", "read_repository", "write_repository", "sudo"},
				"expires_at": "2027-01-01",
			})
		case "/api/v4/user":
			json.NewEncoder(w).Encode(map[string]any{
				"id": 1, "username": "root", "name": "Admin", "is_admin": true,
			})
		case "/api/v4/projects":
			json.NewEncoder(w).Encode([]map[string]any{{
				"id": 1, "path_with_namespace": "root/proj",
			}})
		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]map[string]any{{
				"id": 1, "full_path": "org",
			}})
		case "/api/v4/runners/all":
			json.NewEncoder(w).Encode([]map[string]any{{
				"id": 1, "description": "runner-1",
			}})
		case "/api/v4/users":
			json.NewEncoder(w).Encode([]map[string]any{{
				"id": 1, "username": "root",
			}})
		case "/api/v4/application/settings":
			json.NewEncoder(w).Encode(map[string]any{
				"signup_enabled": true,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	profile, err := ProbeToken(context.Background(), client)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if profile.Username != "root" {
		t.Errorf("username: got %q, want root", profile.Username)
	}
	if !profile.IsAdmin {
		t.Error("expected IsAdmin=true")
	}
	if len(profile.Scopes) == 0 {
		t.Error("expected scopes from PAT self endpoint")
	}
	// All capabilities should be accessible
	for _, c := range profile.Capabilities {
		if !c.Accessible {
			t.Errorf("capability %q should be accessible for admin token", c.Name)
		}
	}
}

func TestProbeToken_ReadOnlyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			json.NewEncoder(w).Encode(map[string]any{
				"id": 2, "name": "read-token",
				"scopes": []string{"read_api"},
			})
		case "/api/v4/user":
			json.NewEncoder(w).Encode(map[string]any{
				"id": 5, "username": "dev", "is_admin": false,
			})
		case "/api/v4/projects":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/runners/all":
			w.WriteHeader(http.StatusForbidden)
		case "/api/v4/users":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/application/settings":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	profile, err := ProbeToken(context.Background(), client)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if profile.IsAdmin {
		t.Error("expected IsAdmin=false")
	}
	// runners/all and application/settings should be inaccessible
	for _, c := range profile.Capabilities {
		if c.Name == "Admin Runners" && c.Accessible {
			t.Error("Admin Runners should not be accessible for read-only token")
		}
		if c.Name == "Admin Settings" && c.Accessible {
			t.Error("Admin Settings should not be accessible for read-only token")
		}
	}
}

func TestProbeToken_NilClient(t *testing.T) {
	_, err := ProbeToken(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestProbeTokenWithOptions_ReadOnlyProjectInference(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "developer-token", "scopes": []string{"api", "write_repository", "create_runner", "manage_runner"},
			})
		case "/api/v4/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "username": "developer", "is_admin": false})
		case "/api/v4/projects":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": 42, "path_with_namespace": "group/demo", "default_branch": "main",
				"permissions": map[string]any{"project_access": map[string]any{"access_level": 30}},
			}})
		case "/api/v4/groups", "/api/v4/users":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/runners/all", "/api/v4/application/settings":
			w.WriteHeader(http.StatusForbidden)
		case "/api/v4/projects/group/demo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 42, "path_with_namespace": "group/demo", "default_branch": "main",
				"permissions": map[string]any{"project_access": map[string]any{"access_level": 30}},
			})
		case "/api/v4/projects/42/repository/tree", "/api/v4/projects/42/jobs":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/projects/42/protected_branches/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":               "main",
				"push_access_levels": []map[string]any{{"access_level": 40, "access_level_description": "Maintainers"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := gitlabx.New(server.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	profile, err := ProbeTokenWithOptions(context.Background(), client, ProbeOptions{Project: "group/demo"})
	if err != nil {
		t.Fatalf("ProbeTokenWithOptions: %v", err)
	}
	if profile.ProbeMode != "read-only" || !profile.ReadOnly {
		t.Fatalf("probe safety = mode %q read_only %v", profile.ProbeMode, profile.ReadOnly)
	}
	if profile.Project == nil || profile.Project.ID != 42 || profile.Project.AccessLevel != 30 {
		t.Fatalf("project access = %+v", profile.Project)
	}
	assertCapabilityStatus(t, profile, "Read target repository", StatusConfirmed)
	assertCapabilityStatus(t, profile, "Push target repository", StatusInferred)
	assertCapabilityStatus(t, profile, "Push target default branch", StatusDenied)
	assertCapabilityStatus(t, profile, "Manage target project", StatusDenied)
	assertCapabilityStatus(t, profile, "Create target runners", StatusDenied)
	assertCapabilityStatus(t, profile, "Manage target runners", StatusDenied)

	mu.Lock()
	defer mu.Unlock()
	for _, method := range methods {
		if method != http.MethodGet {
			t.Errorf("probe sent state-changing method %q; all requests must be GET", method)
		}
	}
}

func TestProbeTokenWithOptions_MaintainerCanReachProtectedBranch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			_ = json.NewEncoder(w).Encode(map[string]any{"scopes": []string{"api", "write_repository"}})
		case "/api/v4/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 9, "username": "maintainer"})
		case "/api/v4/projects":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/groups", "/api/v4/users", "/api/v4/runners/all":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/application/settings":
			w.WriteHeader(http.StatusForbidden)
		case "/api/v4/projects/group/demo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 42, "path_with_namespace": "group/demo", "default_branch": "main",
				"permissions": map[string]any{"group_access": map[string]any{"access_level": 40}},
			})
		case "/api/v4/projects/42/repository/tree", "/api/v4/projects/42/jobs":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/projects/42/protected_branches/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "main", "push_access_levels": []map[string]any{{"access_level": 40}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := gitlabx.New(server.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	profile, err := ProbeTokenWithOptions(context.Background(), client, ProbeOptions{Project: "group/demo"})
	if err != nil {
		t.Fatalf("ProbeTokenWithOptions: %v", err)
	}
	assertCapabilityStatus(t, profile, "Push target default branch", StatusInferred)
	assertCapabilityStatus(t, profile, "Manage target project", StatusInferred)
	assertCapabilityStatus(t, profile, "Create target runners", StatusInferred)
	assertCapabilityStatus(t, profile, "Manage target runners", StatusInferred)
}

func TestProbeToken_UnknownScopesDoNotOverclaimWrites(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v4/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 12, "username": "unknown-scope"})
		case "/api/v4/projects":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": 99, "permissions": map[string]any{"project_access": map[string]any{"access_level": 40}},
			}})
		case "/api/v4/groups", "/api/v4/users":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v4/runners/all", "/api/v4/application/settings":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := gitlabx.New(server.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	profile, err := ProbeToken(context.Background(), client)
	if err != nil {
		t.Fatalf("ProbeToken: %v", err)
	}
	if profile.ScopesKnown {
		t.Fatal("scopes should be unknown when PAT self-introspection is unavailable")
	}
	assertCapabilityStatus(t, profile, "Write repositories", StatusUnknown)
	assertCapabilityStatus(t, profile, "Create runners", StatusUnknown)
	assertCapabilityStatus(t, profile, "Manage runners", StatusUnknown)
}

func assertCapabilityStatus(t *testing.T, profile *TokenProfile, name string, want CapabilityStatus) {
	t.Helper()
	for _, capability := range profile.Capabilities {
		if capability.Name == name {
			if capability.Status != want {
				t.Fatalf("capability %q status = %q, want %q (evidence: %v)", name, capability.Status, want, capability.Evidence)
			}
			return
		}
	}
	t.Fatalf("capability %q not found in %+v", name, profile.Capabilities)
}
