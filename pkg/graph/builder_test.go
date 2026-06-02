package graph

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func mustParse(t *testing.T, y string) *pipeline.Document {
	t.Helper()
	d, err := pipeline.Parse(bytes.NewBufferString(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func TestBuild_StagesFallbackEdges(t *testing.T) {
	y := `
stages: [build, test]

job1:
  stage: build
  script: ["echo build"]
job2:
  stage: test
  script: ["echo test"]
`
	doc := mustParse(t, y)
	g, err := Build(doc)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Expect edge job1 -> job2
	succ := strings.Join(g.Successors("job1"), ",")
	if !strings.Contains(succ, "job2") {
		t.Fatalf("expected edge job1->job2, succ: %v", g.Successors("job1"))
	}
}

func TestBuild_NeedsEdgesAndTags(t *testing.T) {
	y := `
jobA:
  stage: build
  script: ["echo a"]
  tags: ["docker"]
jobB:
  stage: build
  script: ["echo b"]
  needs: ["jobA"]
`
	doc := mustParse(t, y)
	g, err := Build(doc)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Edge jobA->jobB due to needs
	p := strings.Join(g.Predecessors("jobB"), ",")
	if !strings.Contains(p, "jobA") {
		t.Fatalf("expected pred jobA for jobB, got %v", g.Predecessors("jobB"))
	}
	ids := g.NodesWithTag("docker")
	if len(ids) != 1 || ids[0] != "jobA" {
		t.Fatalf("unexpected tag index: %v", ids)
	}
}

func TestBuild_CycleDetection(t *testing.T) {
	y := `
job1:
  stage: build
  script: ["echo 1"]
  needs: ["job2"]
job2:
  stage: build
  script: ["echo 2"]
  needs: ["job1"]
`
	doc := mustParse(t, y)
	if _, err := Build(doc); err == nil {
		t.Fatalf("expected cycle error")
	}
}
