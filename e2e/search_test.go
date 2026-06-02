//go:build e2e

package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSearch_ByName_FindsVulnProject(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--json")
	if err != nil {
		t.Fatalf("search --json failed: %v\nstderr: %s", err, stderr)
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal search JSON: %v\nraw: %s", err, stdout)
	}

	found := false
	for _, r := range results {
		if path, ok := r["path_with_namespace"].(string); ok && path == testVulnProject {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %s in search results; got %d results", testVulnProject, len(results))
	}
}

func TestSearch_PathExists_GitlabCI(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--path-exists", ".gitlab-ci.yml", "--json")
	if err != nil {
		t.Fatalf("search --path-exists failed: %v\nstderr: %s", err, stderr)
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	found := false
	for _, r := range results {
		if path, ok := r["path_with_namespace"].(string); ok && path == testVulnProject {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %s to have .gitlab-ci.yml; got %d results", testVulnProject, len(results))
	}
}

func TestSearch_CodeContent_FindsCI(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--code-content", "stages:", "--json")
	if err != nil {
		t.Fatalf("search --code-content failed: %v\nstderr: %s", err, stderr)
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Error("expected at least one project with 'stages:' in code content")
	}
}

func TestSearch_TextOutput_ContainsProject(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln")
	if err != nil {
		t.Fatalf("search (text) failed: %v\nstderr: %s", err, stderr)
	}

	if !strings.Contains(stdout, testVulnProject) {
		t.Errorf("expected text output to contain %s; got:\n%s", testVulnProject, stdout)
	}
}

func TestSearch_NoResults_NonexistentQuery(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "zzz_nonexistent_xyzzy_12345", "--json")
	if err != nil {
		t.Fatalf("search (no results) failed: %v\nstderr: %s", err, stderr)
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, stdout)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for nonsense query; got %d", len(results))
	}
}

func TestSearch_JSONLFormat(t *testing.T) {
	tok := requireCreds(t)
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--format", "jsonl")
	if err != nil {
		t.Fatalf("search --format jsonl failed: %v\nstderr: %s", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		t.Skip("no JSONL lines returned; vuln project may not be accessible")
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %v\nline: %s", i, err, line)
		}
	}
}
