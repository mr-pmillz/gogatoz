package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIdents_FromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.txt")
	content := "\n# comment\n group/proj1 \n42\n42\n\n\tgroup/proj2\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ids, err := loadIdents(p)
	if err != nil {
		t.Fatalf("loadIdents error: %v", err)
	}
	// Expect 4 non-empty, non-comment lines with whitespace trimmed; duplicates preserved here
	if len(ids) != 4 {
		t.Fatalf("expected 4 identifiers, got %d: %v", len(ids), ids)
	}
	if ids[0] != "group/proj1" || ids[1] != "42" || ids[2] != "42" || ids[3] != "group/proj2" {
		t.Fatalf("unexpected identifiers order/content: %v", ids)
	}
}
