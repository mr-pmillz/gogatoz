package bloodhound

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestExportToWriter(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")
	b.AddEnumerateResults([]enumerate.Result{
		{
			ProjectID:         1,
			ProjectPathWithNS: "team/app",
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityHigh, Title: "Exposed", Evidence: "tags=[shell]", JobName: "build"},
			},
			RunnerTagHits: map[string]int{"shell": 1},
		},
	})

	var buf bytes.Buffer
	if err := ExportToWriter(b, &buf); err != nil {
		t.Fatalf("ExportToWriter: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}

	fileNames := make(map[string]bool)
	for _, f := range zr.File {
		fileNames[f.Name] = true
	}

	if !fileNames["seed_data.json"] {
		t.Error("ZIP missing seed_data.json")
	}
	if !fileNames["cicd-data.json"] {
		t.Error("ZIP missing cicd-data.json")
	}

	// Validate cicd-data.json is valid OpenGraph JSON
	for _, f := range zr.File {
		if f.Name == "cicd-data.json" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open cicd-data.json: %v", err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("read cicd-data.json: %v", err)
			}

			var payload map[string]any
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatalf("cicd-data.json invalid JSON: %v", err)
			}

			meta, _ := payload["metadata"].(map[string]any)
			if meta["source_kind"] != SourceKind {
				t.Errorf("source_kind = %v, want %s", meta["source_kind"], SourceKind)
			}

			graph, _ := payload["graph"].(map[string]any)
			nodes, _ := graph["nodes"].([]any)
			edges, _ := graph["edges"].([]any)
			if len(nodes) == 0 {
				t.Error("expected nodes in cicd-data.json")
			}
			if len(edges) == 0 {
				t.Error("expected edges in cicd-data.json")
			}
		}
	}
}

func TestExportEmptyBuilder(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")
	var buf bytes.Buffer
	if err := ExportToWriter(b, &buf); err != nil {
		t.Fatalf("ExportToWriter empty: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}

	if len(zr.File) != 2 {
		t.Errorf("expected 2 files in ZIP, got %d", len(zr.File))
	}
}
