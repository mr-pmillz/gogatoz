package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractProjectID_SearchOutput(t *testing.T) {
	obj := map[string]any{"id": float64(42), "path_with_namespace": "group/proj"}
	id, ok := extractProjectID(obj)
	if !ok || id != 42 {
		t.Fatalf("expected 42, got %d (ok=%v)", id, ok)
	}
}

func TestExtractProjectID_EnumerateOutput(t *testing.T) {
	obj := map[string]any{"project_id": float64(99), "path_with_namespace": "g/p"}
	id, ok := extractProjectID(obj)
	if !ok || id != 99 {
		t.Fatalf("expected 99, got %d (ok=%v)", id, ok)
	}
}

func TestExtractProjectID_PreferProjectID(t *testing.T) {
	// If both fields exist, project_id wins (enumerate style)
	obj := map[string]any{"id": float64(1), "project_id": float64(2)}
	id, ok := extractProjectID(obj)
	if !ok || id != 2 {
		t.Fatalf("expected 2 (project_id), got %d", id)
	}
}

func TestExtractProjectID_Missing(t *testing.T) {
	obj := map[string]any{"name": "foo"}
	_, ok := extractProjectID(obj)
	if ok {
		t.Fatal("expected ok=false for missing ID")
	}
}

func TestDedup_SearchJSONL(t *testing.T) {
	input := strings.Join([]string{
		`{"id":1,"path_with_namespace":"a/b","web_url":"https://x/a/b","visibility":"public"}`,
		`{"id":2,"path_with_namespace":"c/d","web_url":"https://x/c/d","visibility":"private"}`,
		`{"id":1,"path_with_namespace":"a/b","web_url":"https://x/a/b","visibility":"public"}`,
		`{"id":3,"path_with_namespace":"e/f","web_url":"https://x/e/f","visibility":"internal"}`,
		`{"id":2,"path_with_namespace":"c/d","web_url":"https://x/c/d","visibility":"private"}`,
	}, "\n")

	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "jsonl"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Parse output lines
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 unique lines, got %d: %s", len(lines), stdout.String())
	}

	// Verify order preserved (first occurrence)
	var ids []float64
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("unmarshal line: %v", err)
		}
		ids = append(ids, obj["id"].(float64))
	}
	if ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("expected IDs [1,2,3], got %v", ids)
	}

	// Verify stats on stderr
	if !strings.Contains(stderr.String(), "3 unique from 5 total") {
		t.Fatalf("expected stats in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "2 duplicates removed") {
		t.Fatalf("expected duplicate count in stderr, got: %s", stderr.String())
	}
}

func TestDedup_EnumerateJSONL(t *testing.T) {
	input := strings.Join([]string{
		`{"project_id":10,"path_with_namespace":"g/a","web_url":"https://x/g/a","findings":[]}`,
		`{"project_id":20,"path_with_namespace":"g/b","web_url":"https://x/g/b","findings":[{"id":"F1"}]}`,
		`{"project_id":10,"path_with_namespace":"g/a","web_url":"https://x/g/a","findings":[]}`,
	}, "\n")

	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "jsonl"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 unique lines, got %d", len(lines))
	}
}

func TestDedup_EmptyInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "jsonl"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("expected empty output, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "0 unique from 0 total") {
		t.Fatalf("expected empty stats, got: %s", stderr.String())
	}
}

func TestDedup_AllDuplicates(t *testing.T) {
	input := `{"id":1,"path_with_namespace":"a/b"}
{"id":1,"path_with_namespace":"a/b"}
{"id":1,"path_with_namespace":"a/b"}`

	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "jsonl"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 unique line, got %d", len(lines))
	}
	if !strings.Contains(stderr.String(), "2 duplicates removed") {
		t.Fatalf("expected 2 duplicates, got: %s", stderr.String())
	}
}

func TestDedup_JSONOutput(t *testing.T) {
	input := `{"id":1,"path_with_namespace":"a/b"}
{"id":2,"path_with_namespace":"c/d"}
{"id":1,"path_with_namespace":"a/b"}`

	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var arr []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &arr); err != nil {
		t.Fatalf("unmarshal JSON array: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 items in JSON array, got %d", len(arr))
	}
}

func TestDedup_SkipsInvalidLines(t *testing.T) {
	input := `{"id":1,"path_with_namespace":"a/b"}
not-json-line
{"id":2,"path_with_namespace":"c/d"}`

	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "jsonl"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 valid lines, got %d", len(lines))
	}
	if !strings.Contains(stderr.String(), "1 lines skipped") {
		t.Fatalf("expected skipped count, got: %s", stderr.String())
	}
}

func TestDedup_TextOutput(t *testing.T) {
	input := `{"id":1,"path_with_namespace":"a/b","web_url":"https://x/a/b","visibility":"public","last_activity_at":"2025-01-15T10:00:00Z"}
{"id":2,"path_with_namespace":"c/d","web_url":"https://x/c/d","visibility":"private","last_activity_at":"2025-02-01T12:00:00Z"}`

	var stdout, stderr bytes.Buffer
	cmd := rootCmd
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"parse", "dedup", "--input", "-", "--format", "text"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	out := stdout.String()
	// Table should contain project paths and headers
	if !strings.Contains(out, "a/b") {
		t.Fatalf("expected a/b in table, got: %s", out)
	}
	if !strings.Contains(out, "c/d") {
		t.Fatalf("expected c/d in table, got: %s", out)
	}
	if !strings.Contains(out, "ID") {
		t.Fatalf("expected header ID in table, got: %s", out)
	}
}
