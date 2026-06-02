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

func TestPipe_SearchToEnumerate(t *testing.T) {
	tok := requireCreds(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Build the two commands: search produces JSONL, enumerate consumes via stdin.
	searchCmd := exec.CommandContext(ctx, binaryPath,
		"--gitlab-url", testGitlabURL, "--token", tok,
		"search", "--query", "vuln", "--format", "jsonl")
	searchCmd.Env = append(os.Environ(), "GOGATOZ_CONFIG=")

	enumCmd := exec.CommandContext(ctx, binaryPath,
		"--gitlab-url", testGitlabURL, "--token", tok,
		"enumerate", "--input", "-", "--json")
	enumCmd.Env = append(os.Environ(), "GOGATOZ_CONFIG=")

	// Pipe search stdout → enumerate stdin.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	searchCmd.Stdout = pw
	enumCmd.Stdin = pr

	var enumOut, enumErr bytes.Buffer
	enumCmd.Stdout = &enumOut
	enumCmd.Stderr = &enumErr

	var searchErr bytes.Buffer
	searchCmd.Stderr = &searchErr

	// Start both processes.
	if err := searchCmd.Start(); err != nil {
		t.Fatalf("start search: %v", err)
	}
	if err := enumCmd.Start(); err != nil {
		t.Fatalf("start enumerate: %v", err)
	}

	// Wait for search to finish, then close the write end of the pipe
	// so enumerate sees EOF on stdin.
	if err := searchCmd.Wait(); err != nil {
		t.Fatalf("search failed: %v\nstderr: %s", err, searchErr.String())
	}
	pw.Close()

	if err := enumCmd.Wait(); err != nil {
		t.Fatalf("enumerate failed: %v\nstderr: %s", err, enumErr.String())
	}

	stdout := enumOut.String()
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("enumerate produced no output from piped search")
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("unmarshal piped enumerate JSON: %v\nraw: %s", err, stdout)
	}

	if len(results) == 0 {
		t.Error("expected at least one enumerate result from piped search")
	}
}
