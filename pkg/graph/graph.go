package graph

import (
	"fmt"
	"slices"
	"sort"
)

// NodeType identifies the kind of node represented in the graph.
type NodeType string

const (
	NodeJob      NodeType = "job"
	NodeWorkflow NodeType = "workflow"
	NodeRepo     NodeType = "repo"
)

// Node is the minimal interface for graph nodes.
// Implementations may wrap richer structs from other packages.
type Node interface {
	ID() string
	Type() NodeType
	Tags() []string
}

// JobNode represents a GitLab CI job in the execution graph.
// It keeps a minimal projection required for graph analysis and tagging.
type JobNode struct {
	Name    string
	Stage   string
	Needs   []string
	TagList []string
}

func (n *JobNode) ID() string     { return n.Name }
func (n *JobNode) Type() NodeType { return NodeJob }
func (n *JobNode) Tags() []string { return append([]string(nil), n.TagList...) }

// WorkflowNode optionally represents the workflow/document as a node.
// Not strictly needed for job-level analysis but provided for completeness.
type WorkflowNode struct{ Name string }

func (n *WorkflowNode) ID() string     { return n.Name }
func (n *WorkflowNode) Type() NodeType { return NodeWorkflow }
func (n *WorkflowNode) Tags() []string { return nil }

// RepoNode optionally represents a repository/project in cross-repo graphs.
// Currently unused by the builder but available for future extensions.
type RepoNode struct{ Path string }

func (n *RepoNode) ID() string     { return n.Path }
func (n *RepoNode) Type() NodeType { return NodeRepo }
func (n *RepoNode) Tags() []string { return nil }

// Graph is a directed graph with adjacency lists and a simple tag index.
type Graph struct {
	Nodes    map[string]Node
	Succ     map[string][]string // outgoing edges: node -> successors
	Pred     map[string][]string // incoming edges: node -> predecessors
	TagIndex map[string][]string // tag -> node IDs
}

// New returns an empty graph instance.
func New() *Graph {
	return &Graph{
		Nodes:    map[string]Node{},
		Succ:     map[string][]string{},
		Pred:     map[string][]string{},
		TagIndex: map[string][]string{},
	}
}

// AddNode registers a node with the graph and indexes its tags.
func (g *Graph) AddNode(n Node) {
	if n == nil {
		return
	}
	id := n.ID()
	if id == "" {
		return
	}
	if g.Nodes == nil {
		g.Nodes = map[string]Node{}
	}
	g.Nodes[id] = n
	// ensure empty adjacency lists exist for convenience
	if g.Succ == nil {
		g.Succ = map[string][]string{}
	}
	if g.Pred == nil {
		g.Pred = map[string][]string{}
	}
	if _, ok := g.Succ[id]; !ok {
		g.Succ[id] = nil
	}
	if _, ok := g.Pred[id]; !ok {
		g.Pred[id] = nil
	}
	// tags index
	if g.TagIndex == nil {
		g.TagIndex = map[string][]string{}
	}
	for _, t := range n.Tags() {
		if t == "" {
			continue
		}
		lst := g.TagIndex[t]
		// avoid duplicates
		seen := slices.Contains(lst, id)
		if !seen {
			g.TagIndex[t] = append(lst, id)
		}
	}
}

// AddEdge adds a directed edge from -> to.
func (g *Graph) AddEdge(fromID, toID string) {
	if fromID == "" || toID == "" || fromID == toID {
		return
	}
	if g.Succ == nil {
		g.Succ = map[string][]string{}
	}
	if g.Pred == nil {
		g.Pred = map[string][]string{}
	}
	// ensure nodes exist in maps even if not previously added
	if _, ok := g.Succ[fromID]; !ok {
		g.Succ[fromID] = nil
	}
	if _, ok := g.Pred[toID]; !ok {
		g.Pred[toID] = nil
	}
	// avoid duplicates
	addUnique := func(m map[string][]string, k, v string) {
		lst := m[k]
		if slices.Contains(lst, v) {
			return
		}
		m[k] = append(lst, v)
	}
	addUnique(g.Succ, fromID, toID)
	addUnique(g.Pred, toID, fromID)
}

// Successors returns the sorted list of successor node IDs.
func (g *Graph) Successors(id string) []string {
	lst := append([]string(nil), g.Succ[id]...)
	sort.Strings(lst)
	return lst
}

// Predecessors returns the sorted list of predecessor node IDs.
func (g *Graph) Predecessors(id string) []string {
	lst := append([]string(nil), g.Pred[id]...)
	sort.Strings(lst)
	return lst
}

// NodesWithTag returns IDs of nodes that carry the given tag.
func (g *Graph) NodesWithTag(tag string) []string {
	lst := append([]string(nil), g.TagIndex[tag]...)
	sort.Strings(lst)
	return lst
}

// TopoSort returns a topological ordering of node IDs or an error if a cycle exists.
func (g *Graph) TopoSort() ([]string, error) {
	// compute in-degree
	in := map[string]int{}
	for id := range g.Nodes {
		in[id] = 0
	}
	for to, preds := range g.Pred {
		if _, ok := in[to]; !ok {
			in[to] = 0
		}
		in[to] += len(preds)
	}
	// queue of zero in-degree
	var q []string
	for id, deg := range in {
		if deg == 0 {
			q = append(q, id)
		}
	}
	sort.Strings(q)
	var order []string
	// use a scratch copy of adjacency
	succ := map[string][]string{}
	for k, v := range g.Succ {
		succ[k] = append([]string(nil), v...)
	}
	for len(q) > 0 {
		// pop front
		cur := q[0]
		q = q[1:]
		order = append(order, cur)
		for _, nb := range succ[cur] {
			in[nb]--
			if in[nb] == 0 {
				pos := sort.SearchStrings(q, nb)
				q = slices.Insert(q, pos, nb)
			}
		}
	}
	if len(order) != len(g.Nodes) {
		return nil, fmt.Errorf("cycle detected in graph")
	}
	return order, nil
}
