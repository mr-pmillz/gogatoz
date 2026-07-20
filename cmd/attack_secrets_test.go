package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

type fakeSecrets struct {
	gotProject     any
	gotBranch      string
	gotPubkey      string
	gotTags        []string
	gotExfil       attack.ExfilOptions
	retURL         string
	retErr         error
	impersonated   bool
	impersonateErr error
}

func (f *fakeSecrets) ImpersonateMaintainer(_ context.Context, projectID any) error {
	f.gotProject = projectID
	f.impersonated = true
	return f.impersonateErr
}

func (f *fakeSecrets) RunExfil(_ context.Context, projectID any, branch, pubkey string, runnerTags []string, exfil attack.ExfilOptions) (string, string, error) {
	f.gotProject = projectID
	f.gotBranch = branch
	f.gotPubkey = pubkey
	f.gotTags = runnerTags
	f.gotExfil = exfil
	return f.retURL, "ci-test", f.retErr
}

func withFakeSecrets(fr *fakeSecrets) func() {
	orig := newSecretsRunner
	newSecretsRunner = func(gl *gitlabx.Client, baseURL, authorName, authorEmail string, timeout time.Duration) secretsRunner {
		_ = gl
		_ = baseURL
		_ = authorName
		_ = authorEmail
		_ = timeout
		return fr
	}
	return func() { newSecretsRunner = orig }
}

func TestAttack_Secrets_Success_DefaultBranchAndPubkeyTags(t *testing.T) {
	// ensure clean state
	token = "tok"
	gitlabURL = "https://gitlab.local"
	atkTarget = "group/proj"
	atkSecrets = true
	atkCommitCI = false
	atkBranch = "" // default expected
	atkTags = "self-hosted, linux"
	// create pubkey file
	dir := t.TempDir()
	pub := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pub, []byte("PUBLIC KEY"), 0o644); err != nil {
		t.Fatal(err)
	}
	atkPubkeyFile = pub
	fr := &fakeSecrets{retURL: "https://gitlab.local/group/proj/-/pipelines?ref=gogatoz-attack"}
	defer withFakeSecrets(fr)()
	var buf bytes.Buffer
	attackCmd.SetOut(&buf)
	if err := attackCmd.RunE(attackCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Pipeline URL:") {
		t.Fatalf("expected pipeline URL printed, got: %s", out)
	}
	if fr.gotBranch != gogatozAttack {
		t.Fatalf("expected default branch gogatoz-attack, got %q", fr.gotBranch)
	}
	if strings.TrimSpace(fr.gotPubkey) != "PUBLIC KEY" {
		t.Fatalf("expected pubkey content passed, got %q", fr.gotPubkey)
	}
	if len(fr.gotTags) != 2 {
		t.Fatalf("expected 2 tags, got %v", fr.gotTags)
	}
}

func TestAttack_Secrets_ImpersonatesMaintainer(t *testing.T) {
	token = "tok"
	gitlabURL = "https://gitlab.local"
	atkTarget = "group/proj"
	atkSecrets = true
	atkCommitCI = false
	atkBranch = "attack"
	atkTags = ""
	atkPubkeyFile = ""
	atkPrivkeyFile = ""
	atkAutoEncrypt = false
	atkNoWait = true
	atkImpersonateMaintainer = true
	defer func() { atkImpersonateMaintainer = false }()

	fr := &fakeSecrets{retURL: "https://gitlab.local/group/proj/-/pipelines?ref=attack"}
	defer withFakeSecrets(fr)()
	if err := attackCmd.RunE(attackCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fr.impersonated {
		t.Fatal("expected secrets runner to impersonate a maintainer before committing")
	}
}

func TestAttack_ModeSelectionValidation(t *testing.T) {
	// both modes set should error
	token = "tok"
	gitlabURL = "https://gitlab.local"
	atkTarget = "group/proj"
	atkCommitCI = true
	atkSecrets = true
	atkCIInline = "stages: [test]"
	var buf bytes.Buffer
	attackCmd.SetOut(&buf)
	err := attackCmd.RunE(attackCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "select exactly one mode") {
		t.Fatalf("expected mode selection error, got %v", err)
	}
}
