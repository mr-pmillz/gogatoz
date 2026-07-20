package validate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
