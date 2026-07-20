package payloads

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestCommitPrefixMessage_Default(t *testing.T) {
	msg := GenerateCommitPrefixMessage(CommitPrefixOptions{})
	if !strings.HasPrefix(msg, "feat:") {
		t.Errorf("expected default prefix 'feat:', got %q", msg)
	}
	if !strings.Contains(msg, "update dependency versions") {
		t.Errorf("expected default message, got %q", msg)
	}
}

func TestCommitPrefixMessage_CustomPrefix(t *testing.T) {
	msg := GenerateCommitPrefixMessage(CommitPrefixOptions{Prefix: "fix:"})
	if !strings.HasPrefix(msg, "fix:") {
		t.Errorf("expected 'fix:' prefix, got %q", msg)
	}
}

func TestCommitPrefixMessage_PrefixWithoutColon(t *testing.T) {
	msg := GenerateCommitPrefixMessage(CommitPrefixOptions{Prefix: "chore"})
	if !strings.HasPrefix(msg, "chore:") {
		t.Errorf("expected 'chore:' prefix (auto-added colon), got %q", msg)
	}
}

func TestCommitPrefixMessage_CustomMessage(t *testing.T) {
	msg := GenerateCommitPrefixMessage(CommitPrefixOptions{
		Prefix:  "build:",
		Message: "bump golang to 1.24",
	})
	want := "build: bump golang to 1.24"
	if msg != want {
		t.Errorf("got %q, want %q", msg, want)
	}
}

func TestCommitPrefixYAML_Valid(t *testing.T) {
	yaml := GenerateCommitPrefixYAML(CommitPrefixYAMLOptions{})
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v\nYAML:\n%s", err, yaml)
	}
	if len(doc.Jobs) == 0 {
		t.Fatal("expected at least one job")
	}
	if doc.Jobs[0].Name != "lint-check" {
		t.Errorf("expected default job name 'lint-check', got %q", doc.Jobs[0].Name)
	}
}

func TestCommitPrefixYAML_WithTags(t *testing.T) {
	yaml := GenerateCommitPrefixYAML(CommitPrefixYAMLOptions{
		Common: CommonOptions{Tags: []string{"docker"}},
	})
	if !strings.Contains(yaml, "docker") {
		t.Error("expected tag in output")
	}
	_, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
}
