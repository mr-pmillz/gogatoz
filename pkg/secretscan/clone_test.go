package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCloneDestPath(t *testing.T) {
	tests := []struct {
		name      string
		outputDir string
		path      string
		want      string
	}{
		{"simple", "/out", "group/project", "/out/group/project"},
		{"nested", "/out", "org/sub/project", "/out/org/sub/project"},
		{"root_level", "/out", "myproject", "/out/myproject"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CloneDestPath(tt.outputDir, tt.path)
			if got != tt.want {
				t.Errorf("CloneDestPath(%q, %q) = %q, want %q", tt.outputDir, tt.path, got, tt.want)
			}
		})
	}
}

//nolint:gosec // test credentials are intentional
func TestInjectTokenIntoURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		token   string
		want    string
		wantErr bool
	}{
		{
			name:  "basic",
			url:   "https://gitlab.com/group/project.git",
			token: "glpat-abc123",
			want:  "https://oauth2:glpat-abc123@gitlab.com/group/project.git",
		},
		{
			name:  "with_port",
			url:   "https://gitlab.local:8443/org/repo.git",
			token: "mytoken",
			want:  "https://oauth2:mytoken@gitlab.local:8443/org/repo.git",
		},
		{
			name:  "existing_user",
			url:   "https://olduser@gitlab.com/group/project.git",
			token: "newtoken",
			want:  "https://oauth2:newtoken@gitlab.com/group/project.git",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := injectTokenIntoURL(tt.url, tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("injectTokenIntoURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("injectTokenIntoURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDiscoverRepos(t *testing.T) {
	// Create temp directory structure with some git repos
	root := t.TempDir()

	// Create fake repos
	repos := []string{
		"group1/project1",
		"group1/project2",
		"group2/sub/project3",
	}
	for _, r := range repos {
		gitDir := filepath.Join(root, r, ".git")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	// Create a non-repo directory
	if err := os.MkdirAll(filepath.Join(root, "not-a-repo"), 0o750); err != nil {
		t.Fatal(err)
	}

	discovered, err := DiscoverRepos(root)
	if err != nil {
		t.Fatalf("DiscoverRepos() error = %v", err)
	}

	if len(discovered) != 3 {
		t.Errorf("DiscoverRepos() found %d repos, want 3", len(discovered))
	}

	// Verify all expected repos are found
	found := make(map[string]bool)
	for _, d := range discovered {
		rel, _ := filepath.Rel(root, d)
		found[rel] = true
	}
	for _, r := range repos {
		if !found[r] {
			t.Errorf("expected to find repo %q", r)
		}
	}
}

func TestSanitizeOutput(t *testing.T) {
	got := sanitizeOutput("fatal: could not read from remote glpat-secret123\n", "glpat-secret123")
	if got != "fatal: could not read from remote ***" {
		t.Errorf("sanitizeOutput() = %q", got)
	}
}

func TestCloneProject_badURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dest := filepath.Join(t.TempDir(), "repo")

	// Clone using file:// protocol to a nonexistent path — fails instantly
	err := CloneProject(ctx, "file:///nonexistent/path/repo.git", "", dest, 1)
	if err == nil {
		t.Fatal("expected error for invalid clone URL")
	}
}
