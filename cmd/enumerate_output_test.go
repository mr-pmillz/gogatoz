package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// makeFakeEnumerate fake enumerator returns a fixed set of results.
func makeFakeEnumerate(results []enumerate.Result, retErr error) func(ctx context.Context, cl *gitlabx.Client, idents []string, opts enumerate.Options) ([]enumerate.Result, error) {
	return func(_ context.Context, _ *gitlabx.Client, _ []string, _ enumerate.Options) ([]enumerate.Result, error) {
		return results, retErr
	}
}

// TestEnumerate_JSONL_Output_File ...
func TestEnumerate_JSONL_Output_File(t *testing.T) {
	// Prepare fake results: 2 with findings, 1 clean
	res := []enumerate.Result{
		{ProjectID: 1, ProjectPathWithNS: "g/a", WebURL: "https://x/a", Findings: []analyze.Finding{{ID: "X", Severity: analyze.SeverityHigh, Title: "t"}}},
		{ProjectID: 2, ProjectPathWithNS: "g/b", WebURL: "https://x/b", Findings: nil},
		{ProjectID: 3, ProjectPathWithNS: "g/c", WebURL: "https://x/c", Findings: []analyze.Finding{{ID: "Y", Severity: analyze.SeverityLow, Title: "y"}}},
	}
	// Swap in fake enumerator
	origEnum := enumerateFunc
	enumerateFunc = makeFakeEnumerate(res, nil)
	defer func() { enumerateFunc = origEnum }()

	// Minimal globals required by RunE
	token = testTok
	gitlabURL = testGitlabURL

	// Prepare input file with two identifiers (content is irrelevant to fake enumerator)
	dir := t.TempDir()
	in := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(in, []byte("g/a\n g/b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enumInput = in
	// Output file
	out := filepath.Join(dir, "out.jsonl")
	enumOutputPath = out
	enumFormat = fmtJSONL
	onlyFindings = true // filter out the clean entry

	// Execute command directly
	if err := enumerateCmd.RunE(enumerateCmd, nil); err != nil {
		t.Fatalf("enumerate run error: %v", err)
	}
	// Read output and validate JSONL lines
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("open out: %v", err)
	}
	defer func(f *os.File) {
		err = f.Close()
		if err != nil {
			t.Fatalf("close out: %v", err)
		}
	}(f)
	sc := bufio.NewScanner(f)
	var lines int
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		lines++
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("invalid json line: %v", err)
		}
		// Ensure required keys exist
		if _, ok := m["path_with_namespace"]; !ok {
			t.Fatalf("missing path_with_namespace in line json: %v", m)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan jsonl: %v", err)
	}
	// Expect 2 lines (only findings)
	if lines != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", lines)
	}
}
