package cmd

import (
	"os"
	"strings"
	"testing"
)

// type fakeRunner struct{
//	gotProject any
//	gotBranch string
//	gotYAML   string
//	gotMsg    string
//	retURL    string
//	retErr    error
// }

// func (f *fakeRunner) CommitCIPipeline(_ context.Context, projectID any, branch, yamlContent, message string) (string, error) {
//	f.gotProject = projectID
//	f.gotBranch = branch
//	f.gotYAML = yamlContent
//	f.gotMsg = message
//	return f.retURL, f.retErr
// }

// func withFakeAttacker(fr *fakeRunner) func() {
//	orig := newAttacker
//	newAttacker = func(gl *gitlabx.Client, baseURL, authorName, authorEmail string, timeout time.Duration) attackRunner {
//		_ = gl; _ = baseURL; _ = authorName; _ = authorEmail; _ = timeout
//		return fr
//	}
//	return func(){ newAttacker = orig }
// }

func TestAttack_MissingToken(t *testing.T) {
	// ensure clean state
	token = ""
	atkTarget = ""
	atkCommitCI = false
	cmd := attackCmd
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected missing token error, got %v", err)
	}
}

func TestAttack_MissingTarget(t *testing.T) {
	token = testTok
	gitlabURL = testGitlabURL
	cmd := attackCmd
	// set mode and one source but no target
	atkCommitCI = true
	atkCIInline = "stages: [test]"
	atkTarget = ""
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--target") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

// func TestAttack_ContentSourceValidation(t *testing.T) {
//	token = "tok"
//	gitlabURL = "https://gitlab.example.com"
//	cmd := attackCmd
//	atkTarget = "group/proj"
//	atkCommitCI = true
//	atkCIInline = "a"
//	atkCIFile = "b.yml" // two sources
//	atkCIStdin = false
//	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "exactly one CI content source") {
//		t.Fatalf("expected validation error, got %v", err)
//	}
// }

// func TestAttack_Success_InlineYAML_DefaultBranch(t *testing.T) {
//	token = "tok"
//	gitlabURL = "https://gitlab.example.com"
//	atkTarget = "group/proj"
//	atkCommitCI = true
//	atkBranch = "" // expect default gogatoz-attack
//	atkCIInline = "stages: [test]"
//	atkCIFile = ""
//	atkCIStdin = false
//	atkMessage = ""
//	fr := &fakeRunner{retURL: "https://gitlab.example.com/group/proj/-/pipelines?ref=gogatoz-attack"}
//	defer withFakeAttacker(fr)()
//	var buf bytes.Buffer
//	attackCmd.SetOut(&buf)
//	if err := attackCmd.RunE(attackCmd, nil); err != nil {
//		t.Fatalf("unexpected error: %v", err)
//	}
//	out := buf.String()
//	if !strings.Contains(out, "Pipeline URL:") {
//		t.Fatalf("expected printed pipeline URL, got: %s", out)
//	}
//	if fr.gotBranch != "gogatoz-attack" {
//		t.Fatalf("expected default branch gogatoz-attack, got %q", fr.gotBranch)
//	}
//	if strings.TrimSpace(fr.gotYAML) == "" {
//		t.Fatalf("expected YAML content passed to runner")
//	}
// }

func TestLoadCIContent_FileAndStdin(t *testing.T) {
	// temp file case
	f, err := os.CreateTemp(t.TempDir(), "ci-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := "stages: [build]"
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	got, err := loadCIContent("", f.Name(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(got) != content {
		t.Fatalf("content mismatch: %q", got)
	}
	// stdin case
	orig := ioReadAll
	ioReadAll = func(*os.File) ([]byte, error) { return []byte("x: y\n"), nil }
	defer func() { ioReadAll = orig }()
	got2, err := loadCIContent("", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got2, "x: y") {
		t.Fatalf("expected stdin content, got %q", got2)
	}
}

// func TestAttack_RunnerErrorSurfaced(t *testing.T) {
//	token = "tok"
//	gitlabURL = "https://gitlab.example.com"
//	atkTarget = "group/proj"
//	atkCommitCI = true
//	atkBranch = "branch"
//	atkCIInline = "stages: [test]"
//	fr := &fakeRunner{retErr: errors.New("boom")}
//	defer withFakeAttacker(fr)()
//	if err := attackCmd.RunE(attackCmd, nil); err == nil || !strings.Contains(err.Error(), "boom") {
//		t.Fatalf("expected boom error, got %v", err)
//	}
// }
