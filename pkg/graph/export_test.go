package graph

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func mustParsePipeline(t *testing.T, yaml string) *pipeline.Document {
	t.Helper()
	doc, err := pipeline.Parse(bytes.NewBufferString(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return doc
}

func TestWriteDOT_BasicGraph(t *testing.T) {
	doc := mustParsePipeline(t, `
stages:
  - build
  - test
build_job:
  stage: build
  script: echo build
test_job:
  stage: test
  script: echo test
  needs: [build_job]
`)
	g, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := g.WriteDOT(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "digraph pipeline {") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(out, `"build_job"`) {
		t.Error("missing build_job node")
	}
	if !strings.Contains(out, `"test_job"`) {
		t.Error("missing test_job node")
	}
	if !strings.Contains(out, `"build_job" -> "test_job"`) {
		t.Error("missing build_job -> test_job edge")
	}
	if !strings.Contains(out, "cluster_build") {
		t.Error("missing build stage subgraph")
	}
	if !strings.Contains(out, "cluster_test") {
		t.Error("missing test stage subgraph")
	}
}

func TestWriteMermaid_BasicGraph(t *testing.T) {
	doc := mustParsePipeline(t, `
stages:
  - build
  - test
build_job:
  stage: build
  script: echo build
test_job:
  stage: test
  script: echo test
  needs: [build_job]
`)
	g, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := g.WriteMermaid(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "flowchart LR") {
		t.Error("missing flowchart header")
	}
	if !strings.Contains(out, "build_job") {
		t.Error("missing build_job node")
	}
	if !strings.Contains(out, "test_job") {
		t.Error("missing test_job node")
	}
	if !strings.Contains(out, "build_job --> test_job") {
		t.Error("missing build_job --> test_job edge")
	}
	if !strings.Contains(out, `subgraph build`) {
		t.Error("missing build subgraph")
	}
}

func TestWriteDOT_EmptyGraph(t *testing.T) {
	g := New()
	var buf bytes.Buffer
	if err := g.WriteDOT(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "digraph pipeline {") {
		t.Error("missing digraph header")
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("missing closing brace")
	}
}

func TestWriteMermaid_EmptyGraph(t *testing.T) {
	g := New()
	var buf bytes.Buffer
	if err := g.WriteMermaid(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "flowchart LR") {
		t.Error("missing flowchart header")
	}
}

func TestWriteDOT_WithTags(t *testing.T) {
	doc := mustParsePipeline(t, `
stages:
  - build
build_job:
  stage: build
  script: echo build
  tags: [docker, self-hosted]
`)
	g, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := g.WriteDOT(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "tooltip=") {
		t.Error("missing tooltip for tagged node")
	}
	if !strings.Contains(out, "docker") {
		t.Error("tooltip should contain tag 'docker'")
	}
}

func TestWriteDOT_MultiStageImplicitEdges(t *testing.T) {
	doc := mustParsePipeline(t, `
stages:
  - build
  - test
  - deploy
compile:
  stage: build
  script: echo compile
lint:
  stage: build
  script: echo lint
unit_test:
  stage: test
  script: echo test
release:
  stage: deploy
  script: echo deploy
`)
	g, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := g.WriteDOT(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Stage-based fallback: both build jobs should connect to test job
	if !strings.Contains(out, `"compile" -> "unit_test"`) {
		t.Error("missing compile -> unit_test implicit edge")
	}
	if !strings.Contains(out, `"lint" -> "unit_test"`) {
		t.Error("missing lint -> unit_test implicit edge")
	}
	// Three stage subgraphs
	if !strings.Contains(out, "cluster_build") {
		t.Error("missing build cluster")
	}
	if !strings.Contains(out, "cluster_test") {
		t.Error("missing test cluster")
	}
	if !strings.Contains(out, "cluster_deploy") {
		t.Error("missing deploy cluster")
	}
}

func TestWriteMermaid_MultiStageImplicitEdges(t *testing.T) {
	doc := mustParsePipeline(t, `
stages:
  - build
  - test
compile:
  stage: build
  script: echo compile
unit_test:
  stage: test
  script: echo test
`)
	g, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := g.WriteMermaid(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "compile --> unit_test") {
		t.Error("missing compile --> unit_test implicit edge")
	}
}

func TestWriteDOT_SingleNode(t *testing.T) {
	g := New()
	g.AddNode(&JobNode{Name: "lone_job", Stage: "build"})

	var buf bytes.Buffer
	if err := g.WriteDOT(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"lone_job"`) {
		t.Error("missing lone_job node")
	}
	if strings.Contains(out, "->") {
		t.Error("single node graph should have no edges")
	}
}

func TestDotSafe(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"build", "build"},
		{"my-stage", "my_stage"},
		{"a.b:c", "a_b_c"},
	}
	for _, tt := range tests {
		got := dotSafe(tt.in)
		if got != tt.want {
			t.Errorf("dotSafe(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMermaidSafe(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"build_job", "build_job"},
		{"my-job", "my_job"},
		{"deploy(prod)", "deploy_prod_"},
	}
	for _, tt := range tests {
		got := mermaidSafe(tt.in)
		if got != tt.want {
			t.Errorf("mermaidSafe(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
