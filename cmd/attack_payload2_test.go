package cmd

import (
	"strings"
	"testing"
)

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
