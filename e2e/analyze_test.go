//go:build e2e

package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// Each test targets a dedicated vuln repo and asserts the expected finding ID
// appears in the enumerate output.

func requireFinding(t *testing.T, tok, project, wantFindingID string) {
	t.Helper()
	input := writeInputFile(t, project)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--follow-includes", "--json")
	if err != nil {
		t.Fatalf("enumerate %s failed: %v\nstderr: %s", project, err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal enumerate JSON: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatalf("no enumerate results for %s", project)
	}

	for _, r := range results {
		for _, f := range r.Findings {
			if f.ID == wantFindingID {
				t.Logf("found %s (severity: %s) in %s", f.ID, f.Severity, r.PathWithNamespace)
				return
			}
		}
	}

	// Collect actual finding IDs for diagnostic output.
	var ids []string
	for _, r := range results {
		for _, f := range r.Findings {
			ids = append(ids, f.ID)
		}
	}
	t.Errorf("expected finding %s in %s; got findings: [%s]",
		wantFindingID, project, strings.Join(ids, ", "))
}

func TestAnalyze_IncludeRemote(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnIncludeRemote, "INCLUDE_REMOTE")
}

func TestAnalyze_IncludeProjectUnpinned(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnIncludeUnpinned, "INCLUDE_PROJECT_UNPINNED")
}

func TestAnalyze_IncludeComponent(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnIncludeComponent, "INCLUDE_COMPONENT")
}

func TestAnalyze_WorkflowBroadRules(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnWorkflowBroad, "WORKFLOW_BROAD_RULES")
}

func TestAnalyze_SelfHostedExposed(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnSelfHostedExposed, "SELF_HOSTED_EXPOSED")
}

func TestAnalyze_MRTaggedRunner(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnMRTaggedRunner, "MR_TAGGED_RUNNER")
}

func TestAnalyze_RiskyRemoteScript(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnRiskyRemoteScript, "RISKY_REMOTE_SCRIPT")
}

func TestAnalyze_ArtifactsNoExpire(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnArtifactsNoExpire, "ARTIFACTS_NO_EXPIRE")
}

func TestAnalyze_PlaintextSecret(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnPlaintextSecret, "PLAINTEXT_SECRET")
}

func TestAnalyze_VariableInjection(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnVariableInjection, "VARIABLE_INJECTION")
}

func TestAnalyze_ForkMRUnprotected(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnForkMR, "FORK_MR_UNPROTECTED")
}

func TestAnalyze_ArtifactPoisoningRisk(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnArtifactPoisoning, "ARTIFACT_POISONING_RISK")
}

func TestAnalyze_DispatchTOCTOURisk(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnDispatchTOCTOU, "DISPATCH_TOCTOU_RISK")
}

func TestAnalyze_PwnRequestDeployment(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnPwnRequest, "PWN_REQUEST_DEPLOYMENT")
}

func TestAnalyze_PrivilegedRunnerRisk(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnPrivilegedRunner, "PRIVILEGED_RUNNER_RISK")
}

func TestAnalyze_ForkScriptExecution(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnForkScriptExecution, "FORK_SCRIPT_EXECUTION")
}

func TestAnalyze_AIPromptInjection(t *testing.T) {
	tok := requireCreds(t)
	requireFinding(t, tok, vulnAIPromptInjection, "AI_PROMPT_INJECTION")
}
