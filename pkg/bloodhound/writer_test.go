package bloodhound

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestStreamingWriterEmptyGraph(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, SourceKind)
	if err != nil {
		t.Fatalf("NewStreamingWriter: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	meta, _ := result["metadata"].(map[string]any)
	if meta["source_kind"] != SourceKind {
		t.Errorf("source_kind = %v, want %s", meta["source_kind"], SourceKind)
	}

	graph, _ := result["graph"].(map[string]any)
	nodes, _ := graph["nodes"].([]any)
	edges, _ := graph["edges"].([]any)
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
	if len(edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(edges))
	}

	n, e := sw.Stats()
	if n != 0 || e != 0 {
		t.Errorf("Stats = (%d, %d), want (0, 0)", n, e)
	}
}

func TestStreamingWriterNodesAndEdges(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, SourceKind)
	if err != nil {
		t.Fatalf("NewStreamingWriter: %v", err)
	}

	node1 := &Node{ID: "proj-1", Kinds: []string{KindProject}, Properties: map[string]any{"name": "Project A"}}
	node2 := &Node{ID: "proj-2", Kinds: []string{KindProject}, Properties: map[string]any{"name": "Project B"}}
	if err := sw.WriteNode(node1); err != nil {
		t.Fatalf("WriteNode 1: %v", err)
	}
	if err := sw.WriteNode(node2); err != nil {
		t.Fatalf("WriteNode 2: %v", err)
	}

	edge := NewEdge("proj-1", "proj-2", EdgeDependsOn)
	if err := sw.WriteEdge(edge); err != nil {
		t.Fatalf("WriteEdge: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	graph := result["graph"].(map[string]any)
	nodes := graph["nodes"].([]any)
	edges := graph["edges"].([]any)
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}

	n, e := sw.Stats()
	if n != 2 || e != 1 {
		t.Errorf("Stats = (%d, %d), want (2, 1)", n, e)
	}
}

func TestStreamingWriterEdgeDedup(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, SourceKind)
	if err != nil {
		t.Fatalf("NewStreamingWriter: %v", err)
	}

	if err := sw.WriteNode(&Node{ID: "a", Kinds: []string{KindProject}}); err != nil {
		t.Fatal(err)
	}

	edge := NewEdge("a", "a", EdgeContains)
	if err := sw.WriteEdge(edge); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteEdge(edge); err != nil {
		t.Fatal(err)
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	_, e := sw.Stats()
	if e != 1 {
		t.Errorf("expected 1 edge after dedup, got %d", e)
	}
}

func TestStreamingWriterNilEdge(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, SourceKind)
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteEdge(nil); err != nil {
		t.Errorf("WriteEdge(nil) should not error, got: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamingWriterRejectNodeAfterEdge(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, SourceKind)
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteNode(&Node{ID: "a", Kinds: []string{KindProject}}); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteEdge(NewEdge("a", "a", EdgeContains)); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteNode(&Node{ID: "b", Kinds: []string{KindProject}}); err == nil {
		t.Error("expected error writing node after edge")
	}
	_ = sw.Close()
}

func TestStreamingWriterNoSourceKind(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	meta := result["metadata"].(map[string]any)
	if _, ok := meta["source_kind"]; ok {
		t.Error("expected no source_kind in metadata")
	}
}

func TestStreamingWriterTypeStats(t *testing.T) {
	var buf bytes.Buffer
	sw, err := NewStreamingWriter(&buf, SourceKind)
	if err != nil {
		t.Fatal(err)
	}

	if err := sw.WriteNode(&Node{ID: "p1", Kinds: []string{KindProject}}); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteNode(&Node{ID: "p2", Kinds: []string{KindProject}}); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteNode(&Node{ID: "r1", Kinds: []string{KindRunner}}); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteEdge(NewEdge("p1", "p2", EdgeDependsOn)); err != nil {
		t.Fatal(err)
	}
	if err := sw.WriteEdge(NewEdge("p1", "r1", EdgeRunsOn)); err != nil {
		t.Fatal(err)
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	nk, ek := sw.TypeStats()
	if nk[KindProject] != 2 {
		t.Errorf("project node count = %d, want 2", nk[KindProject])
	}
	if nk[KindRunner] != 1 {
		t.Errorf("runner node count = %d, want 1", nk[KindRunner])
	}
	if ek[EdgeDependsOn] != 1 {
		t.Errorf("depends_on edge count = %d, want 1", ek[EdgeDependsOn])
	}
	if ek[EdgeRunsOn] != 1 {
		t.Errorf("runs_on edge count = %d, want 1", ek[EdgeRunsOn])
	}
}

func TestEmbeddedSchemaValid(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(SchemaJSON, &schema); err != nil {
		t.Fatalf("schema.json is not valid JSON: %v", err)
	}
	if schema["schema"] == nil {
		t.Error("schema.json missing 'schema' key")
	}
}

func TestEmbeddedSeedDataValid(t *testing.T) {
	var seed map[string]any
	if err := json.Unmarshal(SeedDataJSON, &seed); err != nil {
		t.Fatalf("seed_data.json is not valid JSON: %v", err)
	}
	graph, ok := seed["graph"].(map[string]any)
	if !ok {
		t.Fatal("seed_data.json missing 'graph' key")
	}
	edges, ok := graph["edges"].([]any)
	if !ok {
		t.Fatal("seed_data.json missing 'edges' array")
	}
	if len(edges) != len(AllRelKinds()) {
		t.Errorf("seed_data has %d edges, but %d relationship kinds defined", len(edges), len(AllRelKinds()))
	}
}
