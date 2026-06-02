package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteJSONL_WritesOneObjectPerLine(t *testing.T) {
	items := []map[string]any{
		{"a": 1},
		{"b": "x"},
	}
	var buf bytes.Buffer
	if err := writeJSONL(&buf, items); err != nil {
		t.Fatalf("writeJSONL error: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != len(items) {
		t.Fatalf("expected %d lines, got %d", len(items), len(lines))
	}
	// validate each line is valid JSON
	for i, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal(ln, &m); err != nil {
			t.Fatalf("line %d not valid json: %v", i, err)
		}
	}
}
