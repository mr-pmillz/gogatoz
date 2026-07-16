package graph

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// EdgeKind annotates the relationship type for cross-project edges.
type EdgeKind string

const (
	EdgeInclude EdgeKind = "include"
	EdgeTrigger EdgeKind = "trigger"
	EdgeNeeds   EdgeKind = "needs"
)

// CrossProjectEdge records a directed relationship between two projects.
type CrossProjectEdge struct {
	From string
	To   string
	Kind EdgeKind
	Via  string // job name or include file that creates the link
}

// CrossProjectGraph extends Graph with edge annotations for cross-project
// relationships (includes, triggers, downstream pipelines).
type CrossProjectGraph struct {
	*Graph
	EdgeAnnotations map[string][]CrossProjectEdge // "from|to" -> edges
}

// BuildCrossProject constructs a graph showing how multiple projects relate
// through CI include directives and trigger/downstream pipeline references.
//
// projects maps project path (e.g., "mygroup/myproject") to its parsed
// pipeline Document. Projects without a Document (nil) are added as
// isolated nodes.
func BuildCrossProject(projects map[string]*pipeline.Document) *CrossProjectGraph {
	g := &CrossProjectGraph{
		Graph:           New(),
		EdgeAnnotations: map[string][]CrossProjectEdge{},
	}
	slog.Info("building cross-project graph", "projects", len(projects))

	for path := range projects {
		g.AddNode(&RepoNode{Path: path})
	}

	for path, doc := range projects {
		if doc == nil {
			continue
		}

		for _, inc := range doc.Includes {
			if inc.Type != pipeline.IncludeProject || inc.Project == "" {
				continue
			}
			target := inc.Project
			g.ensureNode(target)
			g.addAnnotatedEdge(path, target, EdgeInclude, strings.Join(inc.File, ", "))
		}

		for _, job := range doc.Jobs {
			if job.Trigger == nil {
				continue
			}
			target := extractTriggerProject(job.Trigger)
			if target == "" {
				continue
			}
			g.ensureNode(target)
			g.addAnnotatedEdge(path, target, EdgeTrigger, job.Name)
		}
	}

	return g
}

func (g *CrossProjectGraph) ensureNode(path string) {
	if _, exists := g.Nodes[path]; !exists {
		g.AddNode(&RepoNode{Path: path})
	}
}

func (g *CrossProjectGraph) addAnnotatedEdge(from, to string, kind EdgeKind, via string) {
	g.AddEdge(from, to)
	key := from + "|" + to
	g.EdgeAnnotations[key] = append(g.EdgeAnnotations[key], CrossProjectEdge{
		From: from, To: to, Kind: kind, Via: via,
	})
}

func extractTriggerProject(trigger map[string]any) string {
	if p, ok := trigger["project"]; ok {
		if s, ok := p.(string); ok {
			return s
		}
	}
	if inc, ok := trigger["include"]; ok {
		if m, ok := inc.(map[string]any); ok {
			if p, ok := m["project"]; ok {
				if s, ok := p.(string); ok {
					return s
				}
			}
		}
		if items, ok := inc.([]any); ok {
			for _, item := range items {
				if m, ok := item.(map[string]any); ok {
					if p, ok := m["project"]; ok {
						if s, ok := p.(string); ok {
							return s
						}
					}
				}
			}
		}
	}
	return ""
}

// WriteDOT renders a cross-project graph in Graphviz DOT format with
// edge labels showing the relationship type.
func (g *CrossProjectGraph) WriteDOT(w interface{ Write([]byte) (int, error) }) error {
	if _, err := fmt.Fprintln(w, "digraph cross_project {"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  rankdir=LR;"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, `  node [shape=box3d, style="filled", fillcolor="#e8f4fd", fontname="Helvetica"];`); err != nil {
		return err
	}

	ids := g.SortedNodeIDs()
	for _, id := range ids {
		if _, err := fmt.Fprintf(w, "  %q;\n", id); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	edges := g.sortedEdges()
	for _, e := range edges {
		key := e[0] + "|" + e[1]
		label := g.edgeLabel(key)
		if label != "" {
			if _, err := fmt.Fprintf(w, "  %q -> %q [label=%q];\n", e[0], e[1], label); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "  %q -> %q;\n", e[0], e[1]); err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintln(w, "}")
	return err
}

// WriteMermaid renders a cross-project graph in Mermaid flowchart format
// with edge labels showing the relationship type.
func (g *CrossProjectGraph) WriteMermaid(w interface{ Write([]byte) (int, error) }) error {
	if _, err := fmt.Fprintln(w, "flowchart LR"); err != nil {
		return err
	}

	ids := g.SortedNodeIDs()
	for _, id := range ids {
		safe := mermaidSafe(id)
		if _, err := fmt.Fprintf(w, "  %s[[\"%s\"]]\n", safe, id); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	edges := g.sortedEdges()
	for _, e := range edges {
		key := e[0] + "|" + e[1]
		label := g.edgeLabel(key)
		from := mermaidSafe(e[0])
		to := mermaidSafe(e[1])
		if label != "" {
			if _, err := fmt.Fprintf(w, "  %s -->|%s| %s\n", from, label, to); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "  %s --> %s\n", from, to); err != nil {
				return err
			}
		}
	}
	return nil
}

// SortedNodeIDs returns all node IDs sorted alphabetically.
func (g *CrossProjectGraph) SortedNodeIDs() []string {
	ids := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sortStrings(ids)
	return ids
}

func (g *CrossProjectGraph) edgeLabel(key string) string {
	annotations := g.EdgeAnnotations[key]
	if len(annotations) == 0 {
		return ""
	}
	var parts []string
	for _, a := range annotations {
		parts = append(parts, string(a.Kind))
	}
	return strings.Join(dedupStrings(parts), ", ")
}

func dedupStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
