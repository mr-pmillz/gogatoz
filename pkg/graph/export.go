package graph

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
)

// WriteDOT renders the graph in Graphviz DOT format.
func (g *Graph) WriteDOT(w io.Writer) error {
	slog.Debug("exporting graph", "format", "dot", "nodes", len(g.Nodes))
	if _, err := fmt.Fprintln(w, "digraph pipeline {"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  rankdir=LR;"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, `  node [shape=box, style="rounded,filled", fontname="Helvetica"];`); err != nil {
		return err
	}

	stages := g.stageOrder()
	stageNodes := g.nodesByStage()

	for _, stage := range stages {
		nodes := stageNodes[stage]
		if len(nodes) == 0 {
			continue
		}
		label := stage
		if label == "" {
			label = "unknown"
		}
		if _, err := fmt.Fprintf(w, "\n  subgraph cluster_%s {\n", dotSafe(label)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "    label=%q;\n", label); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, `    style="dashed";`); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, `    color="#666666";`); err != nil {
			return err
		}
		sort.Strings(nodes)
		for _, id := range nodes {
			attrs := g.dotNodeAttrs(id)
			if _, err := fmt.Fprintf(w, "    %q%s;\n", id, attrs); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "  }"); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	edges := g.sortedEdges()
	for _, e := range edges {
		if _, err := fmt.Fprintf(w, "  %q -> %q;\n", e[0], e[1]); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(w, "}")
	return err
}

// WriteMermaid renders the graph in Mermaid flowchart format.
func (g *Graph) WriteMermaid(w io.Writer) error {
	slog.Debug("exporting graph", "format", "mermaid", "nodes", len(g.Nodes))
	if _, err := fmt.Fprintln(w, "flowchart LR"); err != nil {
		return err
	}

	stages := g.stageOrder()
	stageNodes := g.nodesByStage()

	for _, stage := range stages {
		nodes := stageNodes[stage]
		if len(nodes) == 0 {
			continue
		}
		label := stage
		if label == "" {
			label = "unknown"
		}
		if _, err := fmt.Fprintf(w, "\n  subgraph %s[%q]\n", mermaidSafe(label), label); err != nil {
			return err
		}
		sort.Strings(nodes)
		for _, id := range nodes {
			tooltip := g.mermaidTooltip(id)
			if _, err := fmt.Fprintf(w, "    %s[%q]%s\n", mermaidSafe(id), id, tooltip); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "  end"); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	edges := g.sortedEdges()
	for _, e := range edges {
		if _, err := fmt.Fprintf(w, "  %s --> %s\n", mermaidSafe(e[0]), mermaidSafe(e[1])); err != nil {
			return err
		}
	}
	return nil
}

func (g *Graph) stageOrder() []string {
	seen := map[string]bool{}
	var stages []string

	var ordered []struct {
		stage string
		idx   int
	}
	for _, n := range g.Nodes {
		jn, ok := n.(*JobNode)
		if !ok {
			continue
		}
		if seen[jn.Stage] {
			continue
		}
		seen[jn.Stage] = true
		ordered = append(ordered, struct {
			stage string
			idx   int
		}{stage: jn.Stage, idx: len(ordered)})
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].idx < ordered[j].idx
	})

	// Topological sort already guarantees a valid order — just use stable sorted
	// stages to keep output deterministic.
	stageSet := map[string]bool{}
	topo, err := g.TopoSort()
	if err == nil {
		for _, id := range topo {
			if jn, ok := g.Nodes[id].(*JobNode); ok {
				if !stageSet[jn.Stage] {
					stageSet[jn.Stage] = true
					stages = append(stages, jn.Stage)
				}
			}
		}
	}
	if len(stages) == 0 {
		for _, o := range ordered {
			stages = append(stages, o.stage)
		}
	}
	return stages
}

func (g *Graph) nodesByStage() map[string][]string {
	m := map[string][]string{}
	for id, n := range g.Nodes {
		if jn, ok := n.(*JobNode); ok {
			m[jn.Stage] = append(m[jn.Stage], id)
		} else {
			m[""] = append(m[""], id)
		}
	}
	return m
}

func (g *Graph) sortedEdges() [][2]string {
	var edges [][2]string
	for from, tos := range g.Succ {
		for _, to := range tos {
			edges = append(edges, [2]string{from, to})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i][0] != edges[j][0] {
			return edges[i][0] < edges[j][0]
		}
		return edges[i][1] < edges[j][1]
	})
	return edges
}

func (g *Graph) dotNodeAttrs(id string) string {
	n, ok := g.Nodes[id]
	if !ok {
		return ""
	}
	jn, ok := n.(*JobNode)
	if !ok {
		return ""
	}
	var parts []string
	if len(jn.TagList) > 0 {
		parts = append(parts, fmt.Sprintf("tooltip=%q", "tags: "+strings.Join(jn.TagList, ", ")))
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, ", ") + "]"
}

func (g *Graph) mermaidTooltip(id string) string {
	n, ok := g.Nodes[id]
	if !ok {
		return ""
	}
	jn, ok := n.(*JobNode)
	if !ok || len(jn.TagList) == 0 {
		return ""
	}
	return ""
}

func dotSafe(s string) string {
	r := strings.NewReplacer(
		" ", "_",
		"-", "_",
		".", "_",
		"/", "_",
		":", "_",
	)
	return r.Replace(s)
}

func mermaidSafe(s string) string {
	r := strings.NewReplacer(
		" ", "_",
		"-", "_",
		".", "_",
		"/", "_",
		":", "_",
		"(", "_",
		")", "_",
		"[", "_",
		"]", "_",
		"{", "_",
		"}", "_",
		"\"", "_",
		"'", "_",
	)
	return r.Replace(s)
}
