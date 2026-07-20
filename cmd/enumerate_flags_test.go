package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// captureEnumerate is a fake that captures the options passed in.
func captureEnumerate(t *testing.T, ch chan enumerate.Options) func(ctx context.Context, cl *gitlabx.Client, idents []string, opts enumerate.Options) ([]enumerate.Result, error) {
	return func(_ context.Context, _ *gitlabx.Client, _ []string, opts enumerate.Options) ([]enumerate.Result, error) {
		ch <- opts
		return []enumerate.Result{}, nil
	}
}

func TestEnumerate_TargetFlagCombinesWithInputAndDeduplicates(t *testing.T) {
	orig := enumerateFunc
	defer func() { enumerateFunc = orig }()

	identsCh := make(chan []string, 1)
	enumerateFunc = func(_ context.Context, _ *gitlabx.Client, idents []string, _ enumerate.Options) ([]enumerate.Result, error) {
		identsCh <- append([]string(nil), idents...)
		return []enumerate.Result{}, nil
	}

	token = testTok
	gitlabURL = testGitlabURL
	dir := t.TempDir()
	in := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(in, []byte("group/from-file\ngroup/direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	enumInput = in
	enumTarget = " group/direct "
	enumFormat = fmtJSONL
	enumOutputPath = filepath.Join(dir, "out.jsonl")
	defer func() {
		enumInput = ""
		enumTarget = ""
		enumFormat = ""
		enumOutputPath = ""
	}()

	if err := enumerateCmd.RunE(enumerateCmd, nil); err != nil {
		t.Fatalf("RunE error: %v", err)
	}
	select {
	case got := <-identsCh:
		want := []string{"group/from-file", "group/direct"}
		if len(got) != len(want) {
			t.Fatalf("identifiers = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("identifiers = %v, want %v", got, want)
			}
		}
	default:
		t.Fatal("no identifiers captured")
	}
}

func TestEnumerate_LogScrape_Flags_Map_To_Options(t *testing.T) {
	// Swap enumerator with capturing fake
	orig := enumerateFunc
	defer func() { enumerateFunc = orig }()
	ch := make(chan enumerate.Options, 1)
	enumerateFunc = captureEnumerate(t, ch)

	// Minimal env/globals required
	token = testTok
	gitlabURL = testGitlabURL

	// Prepare input file with one identifier
	dir := t.TempDir()
	in := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(in, []byte("group/proj\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enumInput = in

	// Set log scrape flags
	logScrape = true
	logMaxPipelines = 5
	logMaxJobs = 7

	// Use JSONL to avoid template execution paths in test
	enumFormat = fmtJSONL
	enumOutputPath = filepath.Join(dir, "out.jsonl")
	onlyFindings = false

	if err := enumerateCmd.RunE(enumerateCmd, nil); err != nil {
		t.Fatalf("RunE error: %v", err)
	}
	// Retrieve captured options
	var got enumerate.Options
	select {
	case got = <-ch:
	default:
		t.Fatalf("no options captured")
	}
	if !got.LogScrape {
		t.Fatalf("expected LogScrape=true, got false")
	}
	if got.LogMaxPipelines != 5 {
		t.Fatalf("expected LogMaxPipelines=5, got %d", got.LogMaxPipelines)
	}
	if got.LogMaxJobs != 7 {
		t.Fatalf("expected LogMaxJobs=7, got %d", got.LogMaxJobs)
	}
}

func TestEnumerate_Redacted_Flag_Maps_To_Options(t *testing.T) {
	// Swap enumerator with capturing fake
	orig := enumerateFunc
	defer func() { enumerateFunc = orig }()
	ch := make(chan enumerate.Options, 1)
	enumerateFunc = captureEnumerate(t, ch)

	// Reset the shared flag var so this test doesn't leak into others.
	defer func() { enumRedact = false }()

	token = testTok
	gitlabURL = testGitlabURL

	dir := t.TempDir()
	in := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(in, []byte("group/proj\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enumInput = in
	enumFormat = fmtJSONL
	enumOutputPath = filepath.Join(dir, "out.jsonl")
	onlyFindings = false

	run := func() enumerate.Options {
		t.Helper()
		if err := enumerateCmd.RunE(enumerateCmd, nil); err != nil {
			t.Fatalf("RunE error: %v", err)
		}
		select {
		case got := <-ch:
			return got
		default:
			t.Fatalf("no options captured")
			return enumerate.Options{}
		}
	}

	// Default: unredacted.
	enumRedact = false
	if got := run(); got.Redact {
		t.Fatalf("expected Redact=false by default, got true")
	}

	// Opt-in: --redacted maps to Options.Redact.
	enumRedact = true
	if got := run(); !got.Redact {
		t.Fatalf("expected Redact=true when --redacted set, got false")
	}
}
