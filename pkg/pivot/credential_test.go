package pivot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractTokens(t *testing.T) { //nolint:gocognit
	tests := []struct {
		name     string
		envVars  map[string]string
		wantKeys []string // expected SourceKey values
		wantMin  int      // minimum number of tokens found
	}{
		{
			name:     "empty env",
			envVars:  map[string]string{},
			wantKeys: nil,
			wantMin:  0,
		},
		{
			name: "GITLAB_TOKEN name match",
			envVars: map[string]string{
				"GITLAB_TOKEN": "glpat-abc123def456ghi789",
				"HOME":         "/home/user",
			},
			wantKeys: []string{"GITLAB_TOKEN"},
			wantMin:  1,
		},
		{
			name: "PRIVATE_TOKEN name match",
			envVars: map[string]string{
				"PRIVATE_TOKEN": "some-token-value",
			},
			wantKeys: []string{"PRIVATE_TOKEN"},
			wantMin:  1,
		},
		{
			name: "CI_JOB_TOKEN name match",
			envVars: map[string]string{
				"CI_JOB_TOKEN": "job-token-xyz",
			},
			wantKeys: []string{"CI_JOB_TOKEN"},
			wantMin:  1,
		},
		{
			name: "GL_TOKEN name match",
			envVars: map[string]string{
				"GL_TOKEN": "glpat-xyz",
			},
			wantKeys: []string{"GL_TOKEN"},
			wantMin:  1,
		},
		{
			name:     "DEPLOY_TOKEN name match",
			envVars:  map[string]string{"DEPLOY_TOKEN": "gldt-deploy123"}, //nolint:gosec // test fixture
			wantKeys: []string{"DEPLOY_TOKEN"},
			wantMin:  1,
		},
		{
			name: "suffix _ACCESS_TOKEN",
			envVars: map[string]string{
				"MY_ACCESS_TOKEN": "glpat-mytoken123",
			},
			wantKeys: []string{"MY_ACCESS_TOKEN"},
			wantMin:  1,
		},
		{
			name: "suffix _PAT",
			envVars: map[string]string{
				"CUSTOM_PAT": "glpat-custom123",
			},
			wantKeys: []string{"CUSTOM_PAT"},
			wantMin:  1,
		},
		{
			name: "glpat- prefix value match",
			envVars: map[string]string{
				"SOME_RANDOM_VAR": "glpat-randomtoken123",
			},
			wantKeys: []string{"SOME_RANDOM_VAR"},
			wantMin:  1,
		},
		{
			name: "gldt- prefix value match",
			envVars: map[string]string{
				"DEPLOY_VAR": "gldt-deploytoken456",
			},
			wantKeys: []string{"DEPLOY_VAR"},
			wantMin:  1,
		},
		{
			name:     "glcbt- prefix value match",
			envVars:  map[string]string{"PROJECT_TOKEN": "glcbt-projecttoken789"}, //nolint:gosec // test fixture
			wantKeys: []string{"PROJECT_TOKEN"},
			wantMin:  1,
		},
		{
			name: "skip CI_JOB_JWT",
			envVars: map[string]string{
				"CI_JOB_JWT":    "eyJhbGciOiJSUzI1...",
				"CI_JOB_JWT_V2": "eyJhbGciOiJSUzI1...",
			},
			wantKeys: nil,
			wantMin:  0,
		},
		{
			name: "skip empty values",
			envVars: map[string]string{
				"GITLAB_TOKEN": "",
			},
			wantKeys: nil,
			wantMin:  0,
		},
		{
			name: "multiple tokens",
			envVars: map[string]string{ //nolint:gosec // test fixture
				"GITLAB_TOKEN":  "glpat-token1",
				"DEPLOY_TOKEN":  "gldt-token2",
				"PATH":          "/usr/bin",
				"HOME":          "/root",
				"RANDOM_SECRET": "glpat-token3",
			},
			wantKeys: []string{"GITLAB_TOKEN", "DEPLOY_TOKEN", "RANDOM_SECRET"},
			wantMin:  3,
		},
		{
			name: "dedup same token value",
			envVars: map[string]string{
				"GITLAB_TOKEN":  "glpat-sametoken",
				"PRIVATE_TOKEN": "glpat-sametoken",
			},
			wantMin: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractTokens(tt.envVars)
			if len(got) < tt.wantMin {
				t.Errorf("ExtractTokens() returned %d tokens, want at least %d", len(got), tt.wantMin)
			}
			if tt.wantKeys != nil {
				gotKeys := make(map[string]bool)
				for _, c := range got {
					gotKeys[c.SourceKey] = true
				}
				for _, k := range tt.wantKeys {
					if !gotKeys[k] {
						t.Errorf("ExtractTokens() missing expected key %q", k)
					}
				}
			}
			// Verify all returned tokens have hashes
			for _, c := range got {
				if c.TokenHash == "" {
					t.Error("token has empty hash")
				}
				if c.Token == "" {
					t.Error("token has empty value")
				}
			}
		})
	}
}

func TestClassifyTokenType(t *testing.T) {
	tests := []struct {
		token    string
		wantType string
	}{
		{"glpat-abc123", "pat"},
		{"gldt-deploy123", "deploy_token"},
		{"glcbt-project789", "project_access_token"},
		{"glrt-runner456", "runner_token"},
		{"some-random-value", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.wantType, func(t *testing.T) {
			got := classifyTokenType(tt.token)
			if got != tt.wantType {
				t.Errorf("classifyTokenType(%q) = %q, want %q", tt.token, got, tt.wantType)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	// Mock GitLab server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/user" {
			tok := r.Header.Get("PRIVATE-TOKEN")
			if tok == "valid-token" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"id":       42,
					"username": "testuser",
					"name":     "Test User",
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Run("valid token", func(t *testing.T) {
		cred, err := ValidateToken(context.Background(), srv.URL, "valid-token")
		if err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}
		if !cred.IsValid {
			t.Error("expected IsValid = true")
		}
		if cred.Username != "testuser" {
			t.Errorf("Username = %q, want testuser", cred.Username)
		}
		if cred.UserID != 42 {
			t.Errorf("UserID = %d, want 42", cred.UserID)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		cred, err := ValidateToken(context.Background(), srv.URL, "bad-token")
		if err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}
		if cred.IsValid {
			t.Error("expected IsValid = false")
		}
	})
}

func TestCredentialStore(t *testing.T) {
	store := NewCredentialStore()

	c1 := &Credential{Token: "tok1", TokenHash: "hash1"}
	c2 := &Credential{Token: "tok2", TokenHash: "hash2"}

	t.Run("add and has", func(t *testing.T) {
		if store.Has("hash1") {
			t.Error("should not have hash1 yet")
		}
		store.Add(c1)
		if !store.Has("hash1") {
			t.Error("should have hash1 after add")
		}
	})

	t.Run("dedup", func(t *testing.T) {
		store.Add(c1) // add again
		if store.Len() != 1 {
			t.Errorf("Len() = %d, want 1", store.Len())
		}
	})

	t.Run("visited tracking", func(t *testing.T) {
		if store.IsVisited("hash1", 100) {
			t.Error("should not be visited yet")
		}
		store.MarkVisited("hash1", 100)
		if !store.IsVisited("hash1", 100) {
			t.Error("should be visited after mark")
		}
		if store.IsVisited("hash1", 200) {
			t.Error("different project should not be visited")
		}
	})

	t.Run("all credentials", func(t *testing.T) {
		store.Add(c2)
		all := store.All()
		if len(all) != 2 {
			t.Errorf("All() returned %d, want 2", len(all))
		}
	})
}
