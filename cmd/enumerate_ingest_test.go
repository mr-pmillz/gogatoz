package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadIdents_Text_AutoDetect(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.txt")
	content := "\n# comment\n group/proj1 \n42\n\n\tgroup/proj2\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// emulate default flag state
	oldFmt := enumInputFormat
	defer func() { enumInputFormat = oldFmt }()
	enumInputFormat = fmtAuto
	ids, err := loadIdents(p)
	if err != nil {
		t.Fatalf("loadIdents error: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 identifiers, got %d: %v", len(ids), ids)
	}
	if ids[0] != "group/proj1" || ids[1] != "42" || ids[2] != "group/proj2" {
		t.Fatalf("unexpected identifiers: %v", ids)
	}
}

func TestLoadIdents_JSONL_AutoDetect(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.jsonl")
	// mix of objects and plain text and comments; first significant char is '{' so auto -> jsonl
	lines := []string{
		"{\"path_with_namespace\": \"grp/a\"}",
		"{\"id\": 123}",
		"# comment",
		" grp/b ", // tolerated as plain line in jsonl mode
		"{\"id\": \"456\"}",
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	oldFmt := enumInputFormat
	defer func() { enumInputFormat = oldFmt }()
	enumInputFormat = fmtAuto
	ids, err := loadIdents(p)
	if err != nil {
		t.Fatalf("loadIdents jsonl error: %v", err)
	}
	if len(ids) != 4 {
		t.Fatalf("expected 4 ids, got %d: %v", len(ids), ids)
	}
	if ids[0] != "grp/a" || ids[1] != "123" || ids[2] != "grp/b" || ids[3] != "456" {
		t.Fatalf("unexpected ids: %v", ids)
	}
}

func TestLoadIdents_JSON_Array_Explicit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.json")
	arr := `[
	  {"path_with_namespace": "grp/x"},
	  {"id": 999},
	  {"id": "1001"},
	  {"ignored": true}
	]`
	if err := os.WriteFile(p, []byte(arr), 0o644); err != nil {
		t.Fatal(err)
	}
	oldFmt := enumInputFormat
	defer func() { enumInputFormat = oldFmt }()
	enumInputFormat = fmtJSON
	ids, err := loadIdents(p)
	if err != nil {
		t.Fatalf("loadIdents json array error: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 ids, got %d: %v", len(ids), ids)
	}
	if ids[0] != "grp/x" || ids[1] != "999" || ids[2] != "1001" {
		t.Fatalf("unexpected ids: %v", ids)
	}
}
