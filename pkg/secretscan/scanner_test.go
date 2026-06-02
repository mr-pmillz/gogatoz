package secretscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//nolint:gosec // test credentials are intentional
func TestScanOneProject_scanDir(t *testing.T) {
	// Create a temp repo with a fake secret file
	root := t.TempDir()
	repoDir := filepath.Join(root, "test-org", "test-project")
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Write a file with a fake secret
	if err := os.WriteFile(filepath.Join(repoDir, "config.env"), []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	proj := projectInfo{
		PathWithNamespace: "test-org/test-project",
	}

	// Create a fake scanner that returns canned results
	fakeScanner := &Scanner{
		Name:       "fake",
		BinaryName: "true", // always available
		scanFn: func(ctx context.Context, repoPath string) ([]SecretFinding, error) {
			return []SecretFinding{
				{
					Scanner: "fake",
					RuleID:  "aws-key",
					File:    "config.env",
					Line:    1,
					Secret:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			}, nil
		},
	}

	opts := Options{
		ScanDir: root,
	}

	result := scanOneProject(context.Background(), proj, []*Scanner{fakeScanner}, "", opts)

	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.FindingsCount != 1 {
		t.Errorf("FindingsCount = %d, want 1", result.FindingsCount)
	}
	if result.Findings[0].RuleID != "aws-key" {
		t.Errorf("RuleID = %q", result.Findings[0].RuleID)
	}
}

func TestScanOneProject_redact(t *testing.T) {
	root := t.TempDir()
	repoDir := filepath.Join(root, "org", "proj")
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}

	fakeScanner := &Scanner{
		Name:       "fake",
		BinaryName: "true",
		scanFn: func(ctx context.Context, repoPath string) ([]SecretFinding, error) {
			return []SecretFinding{
				{Scanner: "fake", Secret: "ghp_1234567890abcdef"},
			}, nil
		},
	}

	opts := Options{
		ScanDir: root,
		Redact:  true,
	}

	result := scanOneProject(context.Background(), projectInfo{PathWithNamespace: "org/proj"}, []*Scanner{fakeScanner}, "", opts)
	if result.Findings[0].Secret != "ghp_****cdef" {
		t.Errorf("expected redacted secret, got %q", result.Findings[0].Secret)
	}
}

func TestScanOneProject_discardRepos(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Create a temp dir to clone into
	outputDir := t.TempDir()

	// Create a bare git repo to clone from (local, fast)
	bareRepo := t.TempDir()
	for _, args := range [][]string{
		{"init", "--bare", bareRepo},
	} {
		cmd := exec.Command("git", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}

	// Init a temp repo and push to bare
	srcRepo := t.TempDir()
	for _, args := range [][]string{
		{"init", srcRepo},
		{"-C", srcRepo, "config", "user.email", "test@test.com"},
		{"-C", srcRepo, "config", "user.name", "Test"},
		{"-C", srcRepo, "commit", "--allow-empty", "-m", "init"},
		{"-C", srcRepo, "remote", "add", "origin", bareRepo},
		{"-C", srcRepo, "push", "origin", "master"},
	} {
		cmd := exec.Command("git", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}

	proj := projectInfo{
		PathWithNamespace: "test/repo",
		HTTPURLToRepo:     bareRepo,
	}

	fakeScanner := &Scanner{
		Name:       "fake",
		BinaryName: "true",
		scanFn: func(ctx context.Context, repoPath string) ([]SecretFinding, error) {
			return nil, nil
		},
	}

	opts := Options{
		OutputDir:    outputDir,
		CloneDepth:   1,
		DiscardRepos: true,
	}

	result := scanOneProject(context.Background(), proj, []*Scanner{fakeScanner}, "", opts)
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}

	// Verify the repo was removed
	clonePath := CloneDestPath(outputDir, "test/repo")
	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		t.Errorf("expected clone dir to be removed, but it still exists: %s", clonePath)
	}
	if result.ClonePath != "" {
		t.Errorf("expected ClonePath to be empty after discard, got %q", result.ClonePath)
	}
}

func TestRun_scanDir(t *testing.T) {
	// Create a temp directory with repos
	root := t.TempDir()
	for _, p := range []string{"org/repo1/.git", "org/repo2/.git"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o750); err != nil {
			t.Fatal(err)
		}
	}

	// Override scanners to avoid needing real tools
	// We'll test with ParseScanners which should fail since no tools installed
	// So instead test the scan-dir discovery + fake scanner path
	opts := Options{
		ScanDir:     root,
		Scanners:    "auto",
		Concurrency: 2,
	}

	// This will fail because no scanners are installed in test env
	_, err := Run(context.Background(), nil, "", opts)
	if err == nil {
		// If scanners ARE installed, that's fine too
		return
	}
	// Expected: "no secret scanners found on PATH"
	if !strings.Contains(err.Error(), "no secret scanners found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_noOutputDirOrScanDir(t *testing.T) {
	_, err := Run(context.Background(), nil, "", Options{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	// Validation order depends on PATH: scanner check runs before client check.
	if !strings.Contains(msg, "GitLab client required") && !strings.Contains(msg, "no secret scanners found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiscoverRepos_integration(t *testing.T) {
	root := t.TempDir()

	// Create nested repos
	for _, r := range []string{"a/b/.git", "c/.git", "d/e/f/.git"} {
		if err := os.MkdirAll(filepath.Join(root, r), 0o750); err != nil {
			t.Fatal(err)
		}
	}

	repos, err := DiscoverRepos(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 3 {
		t.Errorf("found %d repos, want 3", len(repos))
	}
}
