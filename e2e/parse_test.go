//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestParseDedup_SearchPipe(t *testing.T) {
	tok := requireCreds(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// search → parse dedup (JSONL out) → verify
	searchCmd := exec.CommandContext(ctx, binaryPath,
		"--gitlab-url", testGitlabURL, "--token", tok,
		"search", "--query", "vuln", "--format", "jsonl")
	searchCmd.Env = append(os.Environ(), "GOGATOZ_CONFIG=")

	dedupCmd := exec.CommandContext(ctx, binaryPath,
		"parse", "dedup", "--format", "jsonl")
	dedupCmd.Env = append(os.Environ(), "GOGATOZ_CONFIG=")

	// Pipe search stdout → dedup stdin.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	searchCmd.Stdout = pw
	dedupCmd.Stdin = pr

	var dedupOut, dedupErr bytes.Buffer
	dedupCmd.Stdout = &dedupOut
	dedupCmd.Stderr = &dedupErr

	var searchErr bytes.Buffer
	searchCmd.Stderr = &searchErr

	if err := searchCmd.Start(); err != nil {
		t.Fatalf("start search: %v", err)
	}
	if err := dedupCmd.Start(); err != nil {
		t.Fatalf("start dedup: %v", err)
	}

	if err := searchCmd.Wait(); err != nil {
		t.Fatalf("search failed: %v\nstderr: %s", err, searchErr.String())
	}
	pw.Close()

	if err := dedupCmd.Wait(); err != nil {
		t.Fatalf("dedup failed: %v\nstderr: %s", err, dedupErr.String())
	}

	// Verify JSONL output
	stdout := dedupOut.String()
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("dedup produced no output")
	}

	// Each line should be valid JSON with an "id" field
	var count int
	seen := map[int64]struct{}{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSONL line: %v\nline: %s", err, line)
		}
		idRaw, ok := obj["id"]
		if !ok {
			t.Fatalf("missing 'id' field in output: %s", line)
		}
		id := int64(idRaw.(float64))
		if _, dup := seen[id]; dup {
			t.Errorf("duplicate project ID %d in deduped output", id)
		}
		seen[id] = struct{}{}
		count++
	}
	if count == 0 {
		t.Error("expected at least one project in dedup output")
	}

	// Verify stderr stats message
	stderrStr := dedupErr.String()
	if !strings.Contains(stderrStr, "Deduplicated:") {
		t.Errorf("expected stats on stderr; got: %s", stderrStr)
	}
}

func TestParseDedup_DuplicateRemoval(t *testing.T) {
	tok := requireCreds(t)

	// First, get some search results in JSONL
	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--format", "jsonl")
	if err != nil {
		t.Fatalf("search failed: %v\nstderr: %s", err, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Skip("search returned no results")
	}

	// Write duplicated input (same results twice)
	duped := stdout + stdout
	tmpFile := writeInputFile(t, strings.Split(strings.TrimSpace(duped), "\n")...)

	// Run parse dedup on the duplicated file
	stdout2, stderr2, err := runGogatozWithTimeout(t, "", 30*time.Second,
		"parse", "dedup", "--input", tmpFile, "--format", "jsonl")
	if err != nil {
		t.Fatalf("dedup failed: %v\nstderr: %s", err, stderr2)
	}

	// Count original and deduped lines
	origLines := countNonEmptyLines(stdout)
	dedupLines := countNonEmptyLines(stdout2)

	if dedupLines != origLines {
		t.Errorf("expected %d unique lines after dedup of doubled input; got %d", origLines, dedupLines)
	}

	// Verify stats report duplicates removed
	if !strings.Contains(stderr2, "duplicates removed") {
		t.Errorf("expected 'duplicates removed' in stderr; got: %s", stderr2)
	}
}

func TestParseDedup_TextOutput(t *testing.T) {
	tok := requireCreds(t)

	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--format", "jsonl")
	if err != nil {
		t.Fatalf("search failed: %v\nstderr: %s", err, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Skip("search returned no results")
	}

	// Write to temp file
	tmpFile := writeInputFile(t, strings.Split(strings.TrimSpace(stdout), "\n")...)

	// Request text format explicitly
	stdout2, stderr2, err := runGogatozWithTimeout(t, "", 30*time.Second,
		"parse", "dedup", "--input", tmpFile, "--format", "text")
	if err != nil {
		t.Fatalf("dedup --format text failed: %v\nstderr: %s", err, stderr2)
	}

	// Text output should contain the project path
	if !strings.Contains(stdout2, "vuln") {
		t.Errorf("expected pterm table to contain 'vuln'; got:\n%s", stdout2)
	}
}

func TestParseDedup_JSONOutput(t *testing.T) {
	tok := requireCreds(t)

	stdout, stderr, err := runGogatoz(t, tok, "search", "--query", "vuln", "--format", "jsonl")
	if err != nil {
		t.Fatalf("search failed: %v\nstderr: %s", err, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Skip("search returned no results")
	}

	tmpFile := writeInputFile(t, strings.Split(strings.TrimSpace(stdout), "\n")...)

	stdout2, stderr2, err := runGogatozWithTimeout(t, "", 30*time.Second,
		"parse", "dedup", "--input", tmpFile, "--format", "json")
	if err != nil {
		t.Fatalf("dedup --format json failed: %v\nstderr: %s", err, stderr2)
	}

	// Should be a valid JSON array
	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout2), &results); err != nil {
		t.Fatalf("unmarshal JSON: %v\nraw: %s", err, stdout2)
	}
	if len(results) == 0 {
		t.Error("expected at least one result in JSON output")
	}
}

func countNonEmptyLines(s string) int {
	var n int
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
