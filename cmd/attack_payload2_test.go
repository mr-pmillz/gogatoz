package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type fakeAttackRunner struct {
	impersonated bool
	err          error
}

func (f *fakeAttackRunner) CommitCIPipeline(context.Context, any, string, string, string) (string, error) {
	return "", nil
}

func (f *fakeAttackRunner) ImpersonateMaintainer(context.Context, any) error {
	f.impersonated = true
	return f.err
}

func TestRenderPayload_RunnerOnRunner(t *testing.T) {
	// set flags
	atkPayload = "ror"
	atkJobName = "ror"
	atkScriptURL = "https://ex/ps.sh"
	atkOS = "linux"
	atkTags = "self-hosted"
	atkImage = ""
	atkManual = true
	atkArtifactsPath = ""
	atkArtifactsExpire = ""
	defer func() {
		atkPayload = ""
		atkJobName = ""
		atkScriptURL = ""
		atkOS = ""
		atkTags = ""
		atkManual = false
	}()
	y, err := renderPayload()
	if err != nil {
		t.Fatalf("renderPayload error: %v", err)
	}
	if !strings.Contains(y, "Runner-on-Runner") {
		t.Fatalf("expected runner-on-runner banner, got: %s", y)
	}
	if !strings.Contains(y, "curl -sSfL") {
		t.Fatalf("expected curl fetch in linux payload: %s", y)
	}
}

func TestRenderPayload_Secrets(t *testing.T) {
	atkPayload = "secrets"
	atkJobName = "exfil"
	atkWebhook = "https://hook.local/x"
	atkArtifactsPath = "env.txt"
	defer func() { atkPayload = ""; atkJobName = ""; atkWebhook = ""; atkArtifactsPath = "" }()
	y, err := renderPayload()
	if err != nil {
		t.Fatalf("renderPayload error: %v", err)
	}
	if !strings.Contains(y, "Secrets Exfiltration") || !strings.Contains(y, "printenv") {
		t.Fatalf("expected secrets exfil content: %s", y)
	}
}

func TestRenderPayload_FirstClassModes(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		contains string
	}{
		{name: "dependency confusion", payload: "dep-confusion", contains: "npm publish"},
		{name: "runner variable dump", payload: "runner-var-dump", contains: "runner-vars.txt"},
		{name: "workflow exfiltration", payload: "workflow-exfil", contains: "format-results.txt"},
		{name: "release pipeline tamper", payload: "release-tamper-pipeline", contains: "release-env.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atkPayload = tt.payload
			defer func() { atkPayload = "" }()
			rendered, err := renderPayload()
			if err != nil {
				t.Fatalf("renderPayload() error = %v", err)
			}
			if !strings.Contains(rendered, tt.contains) {
				t.Fatalf("payload %q missing %q:\n%s", tt.payload, tt.contains, rendered)
			}
			var document any
			if err := yaml.Unmarshal([]byte(rendered), &document); err != nil {
				t.Fatalf("payload %q is invalid YAML: %v", tt.payload, err)
			}
		})
	}
}

func TestAttack_NewModesParticipateInExclusiveSelection(t *testing.T) {
	tests := []struct {
		name string
		mode *bool
	}{
		{name: "dependency confusion", mode: &atkDepConfusion},
		{name: "runner variable dump", mode: &atkRunnerVarDump},
		{name: "workflow exfiltration", mode: &atkWorkflowExfil},
		{name: "commit prefix", mode: &atkCommitPrefix},
		{name: "release pipeline tamper", mode: &atkReleaseTamperPipeline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token = testTok
			atkTarget = testProject
			atkCommitCI = true
			*tt.mode = true
			defer func() {
				atkCommitCI = false
				*tt.mode = false
			}()
			err := attackCmd.RunE(attackCmd, nil)
			if err == nil || !strings.Contains(err.Error(), "select exactly one mode") {
				t.Fatalf("RunE() error = %v, want exclusive mode selection error", err)
			}
		})
	}
}

func TestApplyAttackImpersonation(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		runnerErr   error
		wantCalled  bool
		wantErrText string
	}{
		{name: "disabled", enabled: false, wantCalled: false},
		{name: "enabled", enabled: true, wantCalled: true},
		{name: "failure", enabled: true, runnerErr: errors.New("lookup failed"), wantCalled: true, wantErrText: "impersonate maintainer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atkImpersonateMaintainer = tt.enabled
			defer func() { atkImpersonateMaintainer = false }()
			runner := &fakeAttackRunner{err: tt.runnerErr}
			err := applyAttackImpersonation(context.Background(), runner, testProject)
			if runner.impersonated != tt.wantCalled {
				t.Fatalf("impersonated = %v, want %v", runner.impersonated, tt.wantCalled)
			}
			if tt.wantErrText == "" && err != nil {
				t.Fatalf("applyAttackImpersonation() error = %v", err)
			}
			if tt.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrText)) {
				t.Fatalf("applyAttackImpersonation() error = %v, want %q", err, tt.wantErrText)
			}
		})
	}
}

// func TestAttack_CommitCI_UsesPayloadSource(t *testing.T) {
//	// Ensure only payload is selected as source
//	atkCIInline, atkCIFile, atkCIStdin = "", "", false
//	// global requirements
//	token = testTok
//	gitlabURL = testGitlabURL
//	// attack flags
//	atkTarget = testProject
//	atkCommitCI = true
//	atkPayload = "pwn-request"
//	atkTargetBranchRegex = "main|prod"
//	atkBranch = ""
//	defer func(){
//		atkPayload = ""; atkTargetBranchRegex = ""; atkCommitCI = false; atkTarget = ""; atkBranch = ""
//	}()
//	fr := &fakeRunner{retURL: fmt.Sprintf("%s/%s/-/pipelines?ref=gogatoz-attack", testGitlabURL, testProject)}
//	defer withFakeAttacker(fr)()
//	var buf bytes.Buffer
//	attackCmd.SetOut(&buf)
//	if err := attackCmd.RunE(attackCmd, nil); err != nil {
//		t.Fatalf("unexpected error: %v", err)
//	}
//	if fr.gotYAML == "" || !strings.Contains(fr.gotYAML, "merge_request_event") {
//		t.Fatalf("expected pwn-request payload YAML used, got: %s", fr.gotYAML)
//	}
// }
