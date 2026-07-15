package bloodhound

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"sync"
)

//go:embed seed_data.json
var SeedDataJSON []byte

//go:embed schema.json
var SchemaJSON []byte

// StreamingWriter writes BloodHound OpenGraph JSON incrementally.
// Nodes must be written before edges. Thread-safe.
type StreamingWriter struct {
	w           io.Writer
	mu          sync.Mutex
	nodeCount   int
	edgeCount   int
	nodesByKind map[string]int
	edgesByKind map[string]int
	firstNode   bool
	firstEdge   bool
	inEdges     bool
	closed      bool
	seenEdges   map[string]bool
}

// NewStreamingWriter creates a writer that emits OpenGraph JSON with
// the given source_kind in the metadata block.
func NewStreamingWriter(w io.Writer, sourceKind string) (*StreamingWriter, error) {
	sw := &StreamingWriter{
		w:           w,
		firstNode:   true,
		firstEdge:   true,
		seenEdges:   make(map[string]bool),
		nodesByKind: make(map[string]int),
		edgesByKind: make(map[string]int),
	}
	if err := sw.writeHeader(sourceKind); err != nil {
		return nil, err
	}
	return sw, nil
}

func (sw *StreamingWriter) writeHeader(sourceKind string) error {
	var header string
	if sourceKind != "" {
		header = "{\n" +
			"  \"metadata\": {\n" +
			"    \"source_kind\": \"" + sourceKind + "\"\n" +
			"  },\n" +
			"  \"graph\": {\n" +
			"    \"nodes\": [\n"
	} else {
		header = "{\n" +
			"  \"metadata\": {},\n" +
			"  \"graph\": {\n" +
			"    \"nodes\": [\n"
	}
	_, err := io.WriteString(sw.w, header)
	return err
}

// WriteNode writes a single node. Must be called before any WriteEdge call.
func (sw *StreamingWriter) WriteNode(node *Node) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return fmt.Errorf("writer is closed")
	}
	if sw.inEdges {
		return fmt.Errorf("cannot write nodes after edges have started")
	}

	if !sw.firstNode {
		if _, err := io.WriteString(sw.w, ",\n"); err != nil {
			return err
		}
	}
	sw.firstNode = false

	data, err := json.Marshal(node)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(sw.w, "      "); err != nil {
		return err
	}
	if _, err := sw.w.Write(data); err != nil {
		return err
	}

	sw.nodeCount++
	if len(node.Kinds) > 0 {
		sw.nodesByKind[node.Kinds[0]]++
	}
	return nil
}

// WriteEdge writes a single edge. Duplicates (by full JSON content) are
// silently skipped. Nil edges are ignored.
func (sw *StreamingWriter) WriteEdge(edge *Edge) error {
	if edge == nil {
		return nil
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return fmt.Errorf("writer is closed")
	}

	edgeJSON, err := json.Marshal(edge)
	if err != nil {
		return err
	}
	edgeKey := string(edgeJSON)
	if sw.seenEdges[edgeKey] {
		return nil
	}
	sw.seenEdges[edgeKey] = true

	if !sw.inEdges {
		if err := sw.transitionToEdges(); err != nil {
			return err
		}
	}

	if !sw.firstEdge {
		if _, err := io.WriteString(sw.w, ",\n"); err != nil {
			return err
		}
	}
	sw.firstEdge = false

	if _, err := io.WriteString(sw.w, "      "); err != nil {
		return err
	}
	if _, err := sw.w.Write(edgeJSON); err != nil {
		return err
	}

	sw.edgeCount++
	sw.edgesByKind[edge.Kind]++
	return nil
}

func (sw *StreamingWriter) transitionToEdges() error {
	_, err := io.WriteString(sw.w, "\n    ],\n    \"edges\": [\n")
	if err != nil {
		return err
	}
	sw.inEdges = true
	return nil
}

// Close finalizes the JSON structure. Must be called when done writing.
func (sw *StreamingWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return nil
	}
	sw.closed = true

	if !sw.inEdges {
		if err := sw.transitionToEdges(); err != nil {
			return err
		}
	}

	_, err := io.WriteString(sw.w, "\n    ]\n  }\n}\n")
	return err
}

// Stats returns the number of nodes and edges written.
func (sw *StreamingWriter) Stats() (nodes, edges int) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.nodeCount, sw.edgeCount
}

// TypeStats returns copies of the per-kind node and edge counts.
func (sw *StreamingWriter) TypeStats() (nodesByKind, edgesByKind map[string]int) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	n := make(map[string]int, len(sw.nodesByKind))
	maps.Copy(n, sw.nodesByKind)
	e := make(map[string]int, len(sw.edgesByKind))
	maps.Copy(e, sw.edgesByKind)
	return n, e
}
