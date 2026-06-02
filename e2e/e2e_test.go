//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testVulnProject = "MrPMillz/vuln"

// Vuln lab repo paths — one per analysis rule / attack module.
const (
	vulnIncludeRemote     = "MrPMillz/vuln-include-remote"
	vulnIncludeUnpinned   = "MrPMillz/vuln-include-unpinned"
	vulnIncludeComponent  = "MrPMillz/vuln-include-component"
	vulnWorkflowBroad     = "MrPMillz/vuln-workflow-broad"
	vulnSelfHostedExposed = "MrPMillz/vuln-self-hosted-exposed"
	vulnMRTaggedRunner    = "MrPMillz/vuln-mr-tagged-runner"
	vulnRiskyRemoteScript = "MrPMillz/vuln-risky-remote-script"
	vulnArtifactsNoExpire = "MrPMillz/vuln-artifacts-no-expire"
	vulnPlaintextSecret   = "MrPMillz/vuln-plaintext-secret"
	vulnVariableInjection = "MrPMillz/vuln-variable-injection"
	vulnForkMR            = "MrPMillz/vuln-fork-mr"
	vulnArtifactPoisoning = "MrPMillz/vuln-artifact-poisoning"
	vulnDispatchTOCTOU    = "MrPMillz/vuln-dispatch-toctou"
	vulnPwnRequest        = "MrPMillz/vuln-pwn-request"
	vulnPrivilegedRunner  = "MrPMillz/vuln-privileged-runner"

	vulnAttackSecrets     = "MrPMillz/vuln-attack-secrets"
	vulnAttackPushCI      = "MrPMillz/vuln-attack-pushci"
	vulnAttackPersistence = "MrPMillz/vuln-attack-persistence"
	vulnAttackROR         = "MrPMillz/vuln-attack-ror"
	vulnAttackWebshell    = "MrPMillz/vuln-attack-webshell"

	vulnForkScriptExecution = "MrPMillz/vuln-fork-script-execution"
	vulnAIPromptInjection   = "MrPMillz/vuln-ai-prompt-injection"

	vulnAttackAIInject = "MrPMillz/vuln-attack-ai-inject"

	vulnAIGatewayCreds   = "MrPMillz/vuln-ai-gateway-creds"
	vulnAIAutoResolution = "MrPMillz/vuln-ai-auto-resolution"
	vulnInputPoisoning   = "MrPMillz/vuln-input-poisoning"

	vulnScriptInjection = "MrPMillz/vuln-script-injection"
	vulnCachePoison     = "MrPMillz/vuln-cache-poison"
	vulnAutoMerge       = "MrPMillz/vuln-auto-merge"
	vulnAttackTamper    = "MrPMillz/vuln-attack-tamper"
	vulnAttackHarvest   = "MrPMillz/vuln-attack-harvest"
)

// testGitlabURL returns the base URL; override with TEST_GITLAB_URL.
var testGitlabURL = envOrDefault("TEST_GITLAB_URL", "https://gitlab.com")

// testRunnerTag is the runner tag used for jobs that must actually execute;
// override with TEST_RUNNER_TAG.
var testRunnerTag = envOrDefault("TEST_RUNNER_TAG", "shell_executor")

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// binaryPath is set by TestMain after a successful build.
var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "gogatoz-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	bin := filepath.Join(tmp, "gogatoz")
	// Build the binary from the project root (one level up from e2e/).
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join(".", "..")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build gogatoz: %v\n", err)
		os.Exit(1)
	}
	binaryPath = bin
	os.Exit(m.Run())
}

// loadTestEnv loads key=value lines from config/test.env if present (best-effort).
// Mirrors pkg/gitlabx/runners_integration_test.go:loadLocalTestEnv.
func loadTestEnv(t *testing.T) {
	t.Helper()
	p := filepath.Join("..", "config", "test.env")
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			_ = os.Setenv(k, v)
		}
	}
}

// requireCreds returns the API token or skips the test.
func requireCreds(t *testing.T) string {
	t.Helper()
	loadTestEnv(t)
	tok := strings.TrimSpace(os.Getenv("TEST_API_PAT"))
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
	}
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("CI_JOB_TOKEN"))
	}
	if tok == "" {
		t.Skip("TEST_API_PAT/CI_JOB_TOKEN not set; skipping E2E test")
	}
	return tok
}

// runGogatoz executes the built binary with default 60s timeout.
func runGogatoz(t *testing.T, token string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return runGogatozWithTimeout(t, token, 60*time.Second, args...)
}

// runGogatozWithTimeout executes the built binary with a custom timeout.
func runGogatozWithTimeout(t *testing.T, token string, timeout time.Duration, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Inject --gitlab-url and --token into args.
	fullArgs := []string{"--gitlab-url", testGitlabURL}
	if token != "" {
		fullArgs = append(fullArgs, "--token", token)
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, binaryPath, fullArgs...)
	// Prevent Viper from reading any local config file.
	cmd.Env = append(os.Environ(), "GOGATOZ_CONFIG=")

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// skipOnInsufficientScope skips the test if the command failed due to a 403
// error (insufficient scope or project-level permission denial).  This is an
// infrastructure prerequisite — the token needs write access to the target
// project, similar to requireCreds checking token presence.
func skipOnInsufficientScope(t *testing.T, err error, stderr string) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(stderr, "insufficient_scope") ||
		strings.Contains(stderr, "http 403") ||
		strings.Contains(stderr, "403 Forbidden") {
		t.Skipf("token lacks required permissions for this test (403): %s", strings.TrimSpace(stderr))
	}
}

// e2eBranchName returns a unique branch name for attack test isolation.
func e2eBranchName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("gogatoz-e2e-%d", time.Now().UnixNano())
}

// writeInputFile creates a temp file with one identifier per line.
func writeInputFile(t *testing.T, idents ...string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "e2e-input-*.txt")
	if err != nil {
		t.Fatalf("create input file: %v", err)
	}
	for _, id := range idents {
		fmt.Fprintln(f, id)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close input file: %v", err)
	}
	return f.Name()
}

// gitlabHTTPClient returns an HTTP client suitable for the test GitLab instance.
func gitlabHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // e2e tests against self-hosted instance
		},
	}
}

// gitlabAPI performs a GET request to the GitLab API and returns the response body.
func gitlabAPI(t *testing.T, tok, path string) []byte {
	t.Helper()
	url := strings.TrimRight(testGitlabURL, "/") + "/api/v4" + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	resp, err := gitlabHTTPClient().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, string(body))
	}
	return body
}

// waitForPipeline polls the latest pipeline on a branch until it reaches a
// terminal state (success, failed, canceled, skipped) or the timeout expires.
// Returns the pipeline status string.
func waitForPipeline(t *testing.T, tok, projectPath, ref string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	encodedProject := strings.ReplaceAll(projectPath, "/", "%2F")
	path := fmt.Sprintf("/projects/%s/pipelines?ref=%s&per_page=1", encodedProject, ref)

	for time.Now().Before(deadline) {
		body := gitlabAPI(t, tok, path)
		var pipelines []struct {
			ID     int    `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &pipelines); err != nil {
			t.Fatalf("unmarshal pipelines: %v", err)
		}
		if len(pipelines) == 0 {
			time.Sleep(2 * time.Second)
			continue
		}
		status := pipelines[0].Status
		switch status {
		case "success", "failed", "canceled", "skipped":
			return status
		}
		t.Logf("pipeline %d status: %s (waiting...)", pipelines[0].ID, status)
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("pipeline on ref %s did not complete within %v", ref, timeout)
	return ""
}

// downloadJobArtifact downloads a specific artifact file from the latest job
// on a branch and returns its content. jobName selects the CI job.
func downloadJobArtifact(t *testing.T, tok, projectPath, ref, artifactPath, jobName string) string {
	t.Helper()
	encodedProject := strings.ReplaceAll(projectPath, "/", "%2F")
	url := fmt.Sprintf("%s/api/v4/projects/%s/jobs/artifacts/%s/raw/%s?job=%s",
		strings.TrimRight(testGitlabURL, "/"), encodedProject, ref, artifactPath, jobName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("create artifact request: %v", err)
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	resp, err := gitlabHTTPClient().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("download artifact: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("download artifact %s: %d %s", artifactPath, resp.StatusCode, string(body))
	}
	return string(body)
}

// protectBranch creates a protected branch rule allowing the bot user to push.
func protectBranch(t *testing.T, tok, projectPath, branch string) {
	t.Helper()
	encodedProject := strings.ReplaceAll(projectPath, "/", "%2F")
	url := fmt.Sprintf("%s/api/v4/projects/%s/protected_branches?name=%s&push_access_level=40&merge_access_level=40",
		strings.TrimRight(testGitlabURL, "/"), encodedProject, branch)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		t.Fatalf("create protect-branch request: %v", err)
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	resp, err := gitlabHTTPClient().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("protect branch %s: %v", branch, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("protect branch %s: %d %s", branch, resp.StatusCode, string(body))
	}
}

// createPipeline triggers a new pipeline on the given ref and returns the pipeline ID.
func createPipeline(t *testing.T, tok, projectPath, ref string) int {
	t.Helper()
	encodedProject := strings.ReplaceAll(projectPath, "/", "%2F")
	url := fmt.Sprintf("%s/api/v4/projects/%s/pipeline?ref=%s",
		strings.TrimRight(testGitlabURL, "/"), encodedProject, ref)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		t.Fatalf("create pipeline request: %v", err)
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	resp, err := gitlabHTTPClient().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("create pipeline on %s: %d %s", ref, resp.StatusCode, string(body))
	}
	var pl struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(body, &pl); err != nil {
		t.Fatalf("unmarshal pipeline response: %v", err)
	}
	return pl.ID
}

// waitForPipelineByID polls a specific pipeline until it reaches a terminal state.
func waitForPipelineByID(t *testing.T, tok, projectPath string, pipelineID int, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	encodedProject := strings.ReplaceAll(projectPath, "/", "%2F")
	path := fmt.Sprintf("/projects/%s/pipelines/%d", encodedProject, pipelineID)

	for time.Now().Before(deadline) {
		body := gitlabAPI(t, tok, path)
		var pl struct {
			ID     int    `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &pl); err != nil {
			t.Fatalf("unmarshal pipeline: %v", err)
		}
		switch pl.Status {
		case "success", "failed", "canceled", "skipped":
			return pl.Status
		}
		t.Logf("pipeline %d status: %s (waiting...)", pipelineID, pl.Status)
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("pipeline %d did not complete within %v", pipelineID, timeout)
	return ""
}

// unprotectBranch removes protection from a branch (best-effort).
func unprotectBranch(t *testing.T, tok, projectPath, branch string) {
	t.Helper()
	encodedProject := strings.ReplaceAll(projectPath, "/", "%2F")
	url := fmt.Sprintf("%s/api/v4/projects/%s/protected_branches/%s",
		strings.TrimRight(testGitlabURL, "/"), encodedProject, branch)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	resp, err := gitlabHTTPClient().Do(req) //nolint:gosec
	if err != nil {
		return
	}
	resp.Body.Close()
}
