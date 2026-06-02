//go:build e2e

package e2e_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// enumerateResult mirrors the subset of enumerate.Result we validate.
type enumerateResult struct {
	ProjectID         int                `json:"project_id"`
	PathWithNamespace string             `json:"path_with_namespace"`
	WebURL            string             `json:"web_url"`
	HasCIPipeline     bool               `json:"has_ci_pipeline"`
	Findings          []enumerateFinding `json:"findings"`
}

type enumerateFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	JobName     string `json:"job_name"`
}

func TestEnumerate_VulnProject_ProducesFindings(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--json")
	if err != nil {
		t.Fatalf("enumerate --json failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal enumerate JSON: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one enumerate result")
	}
	r := results[0]
	if r.PathWithNamespace != testVulnProject {
		t.Errorf("expected path_with_namespace=%s; got %s", testVulnProject, r.PathWithNamespace)
	}
	if !r.HasCIPipeline {
		t.Error("expected has_ci_pipeline=true for vuln project")
	}
	if len(r.Findings) == 0 {
		t.Error("expected at least one finding for the vulnerable project")
	}
	// Verify findings have severity populated.
	for _, f := range r.Findings {
		if f.Severity == "" {
			t.Errorf("finding %q has empty severity", f.ID)
		}
	}
}

func TestEnumerate_VulnProject_HasInjectionFinding(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--json")
	if err != nil {
		t.Fatalf("enumerate failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	found := false
	for _, r := range results {
		for _, f := range r.Findings {
			lower := strings.ToLower(f.ID + " " + f.Title)
			if strings.Contains(lower, "inject") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("expected an injection-related finding in vuln project")
	}
}

func TestEnumerate_WithFollowIncludes(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--follow-includes", "--json")
	if err != nil {
		t.Fatalf("enumerate --follow-includes failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result with --follow-includes")
	}
}

func TestEnumerate_QuickMode(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--mode", "quick", "--json")
	if err != nil {
		t.Fatalf("enumerate --mode quick failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result in quick mode")
	}
	if !results[0].HasCIPipeline {
		t.Error("expected has_ci_pipeline=true in quick mode")
	}
}

func TestEnumerate_DeepMode(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--mode", "deep", "--json")
	if err != nil {
		t.Fatalf("enumerate --mode deep failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result in deep mode")
	}
}

func TestEnumerate_WithRunners(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--runners", "--json")
	if err != nil {
		t.Fatalf("enumerate --runners failed: %v\nstderr: %s", err, stderr)
	}

	var results []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result with --runners")
	}
	// Verify the result has runner-related keys by unmarshaling to map.
	var m map[string]any
	if err := json.Unmarshal(results[0], &m); err != nil {
		t.Fatalf("unmarshal result[0]: %v", err)
	}
	// Runner data may be in "runners" or "runner_summary" — just check command succeeded.
	t.Logf("enumerate --runners keys: %v", mapKeys(m))
}

func TestEnumerate_WithProtectedBranches(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--protected-branches", "--json")
	if err != nil {
		t.Fatalf("enumerate --protected-branches failed: %v\nstderr: %s", err, stderr)
	}

	var results []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result with --protected-branches")
	}
}

func TestEnumerate_TextOutput(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input)
	if err != nil {
		t.Fatalf("enumerate (text) failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, testVulnProject) {
		t.Errorf("expected text output to contain %s; got:\n%s", testVulnProject, stdout)
	}
}

func TestEnumerate_JSONLFormat(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--format", "jsonl")
	if err != nil {
		t.Fatalf("enumerate --format jsonl failed: %v\nstderr: %s", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		t.Fatal("expected at least one JSONL line")
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestEnumerate_OnlyFindings(t *testing.T) {
	tok := requireCreds(t)
	input := writeInputFile(t, testVulnProject)
	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", input, "--only-findings", "--json")
	if err != nil {
		t.Fatalf("enumerate --only-findings failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	// All returned results should have findings (only-findings filters clean projects).
	for _, r := range results {
		if len(r.Findings) == 0 {
			t.Errorf("--only-findings returned project %s with zero findings", r.PathWithNamespace)
		}
	}
}

func TestEnumerate_PipedFromSearch(t *testing.T) {
	tok := requireCreds(t)

	// Step 1: Run search to get JSONL output.
	searchOut, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--format", "jsonl")
	if err != nil {
		t.Fatalf("search for pipe failed: %v\nstderr: %s", err, stderr)
	}
	if strings.TrimSpace(searchOut) == "" {
		t.Skip("search returned no results; cannot test pipe")
	}

	// Step 2: Write search output to a temp file and feed to enumerate via --input.
	tmpFile := writeInputFile(t) // empty — we'll overwrite
	if err := writeFile(tmpFile, searchOut); err != nil {
		t.Fatalf("write pipe input: %v", err)
	}

	stdout, stderr, err := runGogatoz(t, tok, "enumerate", "--input", tmpFile, "--json")
	if err != nil {
		t.Fatalf("enumerate from piped search failed: %v\nstderr: %s", err, stderr)
	}

	var results []enumerateResult
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Error("expected at least one result from piped search→enumerate")
	}
}

// mapKeys returns the keys of a map for logging.
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// writeFile overwrites a file with the given content.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
