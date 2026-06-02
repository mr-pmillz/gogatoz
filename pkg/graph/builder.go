package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Build constructs a job execution graph from a parsed GitLab CI document.
//
// Rules:
//   - Each job becomes a JobNode with its stage, needs, and tags.
//   - If a job declares explicit needs, edges are added from each need -> job.
//   - Otherwise, edges are added from all jobs in the immediately previous stage -> job
//     based on the stage order in doc.Stages. If doc.Stages is empty, no fallback edges are added.
//   - The result is validated with a topological sort; a cycle results in an error.
//
//nolint:gocognit // graph construction kept in one routine for clarity and performance
func Build(doc *pipeline.Document) (*Graph, error) {
	if doc == nil {
		return nil, fmt.Errorf("nil document")
	}
	g := New()
	// Normalize stage order map.
	stageOrder := make([]string, 0, len(doc.Stages))
	stageIndex := map[string]int{}
	for i, s := range doc.Stages {
		ss := strings.TrimSpace(s)
		stageOrder = append(stageOrder, ss)
		stageIndex[ss] = i
	}

	// Collect jobs per stage and all job names for needs validation.
	jobsByStage := map[string][]string{}
	jobSet := map[string]struct{}{}
	for _, j := range doc.Jobs {
		name := strings.TrimSpace(j.Name)
		if name == "" {
			continue
		}
		st := strings.TrimSpace(j.Stage)
		if st == "" {
			st = "" // unknown; will be handled later (no fallback edges if stages list empty)
		}
		// Track unseen stages by appending to the end of order (after declared stages)
		if _, ok := stageIndex[st]; st != "" && !ok {
			stageIndex[st] = len(stageOrder)
			stageOrder = append(stageOrder, st)
		}
		jobsByStage[st] = append(jobsByStage[st], name)
		jobSet[name] = struct{}{}
		g.AddNode(&JobNode{Name: name, Stage: st, Needs: append([]string(nil), j.Needs...), TagList: append([]string(nil), j.Tags...)})
	}

	// Add edges via explicit needs.
	for _, n := range g.Nodes {
		jn, ok := n.(*JobNode)
		if !ok {
			continue
		}
		if len(jn.Needs) == 0 {
			continue
		}
		for _, dep := range jn.Needs {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				continue
			}
			if _, ok := jobSet[dep]; !ok {
				// dangling need; ignore (GitLab would error at runtime but we keep graph robust)
				continue
			}
			g.AddEdge(dep, jn.Name)
		}
	}

	// Add stage-based fallback edges for jobs without explicit needs.
	if len(stageOrder) > 0 {
		// Build reverse map stage -> previous stage (immediate predecessor index)
		prevStage := map[string]string{}
		for i := 1; i < len(stageOrder); i++ {
			prevStage[stageOrder[i]] = stageOrder[i-1]
		}
		for _, n := range g.Nodes {
			jn, ok := n.(*JobNode)
			if !ok {
				continue
			}
			if len(jn.Needs) > 0 {
				continue
			} // explicit needs override stage fallback
			st := jn.Stage
			ps, ok := prevStage[st]
			if !ok {
				continue
			} // first stage or unknown stage
			for _, upstream := range jobsByStage[ps] {
				g.AddEdge(upstream, jn.Name)
			}
		}
	}

	// Validate for cycles
	if _, err := g.TopoSort(); err != nil {
		return nil, err
	}
	return g, nil
}

// SortedJobIDs returns the stable-sorted list of job node IDs present in the graph.
func (g *Graph) SortedJobIDs() []string {
	var ids []string
	for id, n := range g.Nodes {
		if n.Type() == NodeJob {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
