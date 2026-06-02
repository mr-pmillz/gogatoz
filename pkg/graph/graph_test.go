package graph

import (
	"testing"
)

func TestGraph_AddNodeEdgeTopo(t *testing.T) {
	g := New()
	g.AddNode(&JobNode{Name: "a"})
	g.AddNode(&JobNode{Name: "b"})
	g.AddEdge("a", "b")
	// Topo should be a,b
	order, err := g.TopoSort()
	if err != nil {
		t.Fatalf("unexpected topo error: %v", err)
	}
	if len(order) != 2 || order[0] != "a" || order[1] != "b" {
		t.Fatalf("unexpected order: %v", order)
	}
	// Pred/Succ
	s := g.Successors("a")
	if len(s) != 1 || s[0] != "b" {
		t.Fatalf("unexpected succ: %v", s)
	}
	p := g.Predecessors("b")
	if len(p) != 1 || p[0] != "a" {
		t.Fatalf("unexpected pred: %v", p)
	}
}

func TestGraph_TagsIndex(t *testing.T) {
	g := New()
	g.AddNode(&JobNode{Name: "job1", TagList: []string{"docker", "self-hosted"}})
	ids := g.NodesWithTag("docker")
	if len(ids) != 1 || ids[0] != "job1" {
		t.Fatalf("unexpected tag index: %v", ids)
	}
}

func TestGraph_CycleDetect(t *testing.T) {
	g := New()
	g.AddNode(&JobNode{Name: "a"})
	g.AddNode(&JobNode{Name: "b"})
	g.AddEdge("a", "b")
	g.AddEdge("b", "a")
	if _, err := g.TopoSort(); err == nil {
		t.Fatalf("expected cycle error")
	}
}
