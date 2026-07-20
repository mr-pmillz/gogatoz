package graph

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestBuildCrossProject_IncludeEdges(t *testing.T) {
	projA := mustParse(t, `
stages: [build]
include:
  - project: group/project-b
    file: /templates/ci.yml
build:
  stage: build
  script: echo build
`)
	projB := mustParse(t, `
stages: [build]
build:
  stage: build
  script: echo build
`)

	g := BuildCrossProject(map[string]*pipeline.Document{
		"group/project-a": projA,
		"group/project-b": projB,
	})

	succs := g.Successors("group/project-a")
	if len(succs) != 1 || succs[0] != "group/project-b" {
		t.Errorf("expected project-a -> project-b edge, got successors: %v", succs)
	}

	key := "group/project-a|group/project-b"
	anns := g.EdgeAnnotations[key]
	if len(anns) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(anns))
	}
	if anns[0].Kind != EdgeInclude {
		t.Errorf("edge kind = %q, want include", anns[0].Kind)
	}
}

func TestBuildCrossProject_TriggerEdges(t *testing.T) {
	projA := mustParse(t, `
stages: [deploy]
trigger_downstream:
  stage: deploy
  trigger:
    project: group/project-c
    branch: main
`)

	g := BuildCrossProject(map[string]*pipeline.Document{
		"group/project-a": projA,
	})

	if _, exists := g.Nodes["group/project-c"]; !exists {
		t.Error("triggered project group/project-c should be auto-added as a node")
	}

	succs := g.Successors("group/project-a")
	if len(succs) != 1 || succs[0] != "group/project-c" {
		t.Errorf("expected project-a -> project-c trigger edge, got: %v", succs)
	}

	key := "group/project-a|group/project-c"
	anns := g.EdgeAnnotations[key]
	if len(anns) == 0 || anns[0].Kind != EdgeTrigger {
		t.Errorf("expected trigger annotation, got: %+v", anns)
	}
}

func TestBuildCrossProject_NilDocument(t *testing.T) {
	g := BuildCrossProject(map[string]*pipeline.Document{
		"group/project-a": nil,
	})

	if _, exists := g.Nodes["group/project-a"]; !exists {
		t.Error("nil-doc project should still be added as a node")
	}
	if len(g.sortedEdges()) != 0 {
		t.Error("nil-doc project should have no edges")
	}
}

func TestBuildCrossProject_Empty(t *testing.T) {
	g := BuildCrossProject(map[string]*pipeline.Document{})
	if len(g.Nodes) != 0 {
		t.Errorf("empty input should produce empty graph, got %d nodes", len(g.Nodes))
	}
}

func TestCrossProjectGraph_WriteDOT(t *testing.T) {
	projA := mustParse(t, `
stages: [build]
include:
  - project: group/project-b
    file: /templates/ci.yml
build:
  stage: build
  script: echo build
`)

	g := BuildCrossProject(map[string]*pipeline.Document{
		"group/project-a": projA,
		"group/project-b": nil,
	})

	var buf bytes.Buffer
	if err := g.WriteDOT(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "digraph cross_project {") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(out, `"group/project-a"`) {
		t.Error("missing project-a node")
	}
	if !strings.Contains(out, `"group/project-b"`) {
		t.Error("missing project-b node")
	}
	if !strings.Contains(out, `"group/project-a" -> "group/project-b"`) {
		t.Error("missing include edge")
	}
	if !strings.Contains(out, `label="include"`) {
		t.Error("missing include edge label")
	}
}

func TestCrossProjectGraph_WriteMermaid(t *testing.T) {
	projA := mustParse(t, `
stages: [deploy]
trigger_downstream:
  stage: deploy
  trigger:
    project: group/project-c
    branch: main
`)

	g := BuildCrossProject(map[string]*pipeline.Document{
		"group/project-a": projA,
	})

	var buf bytes.Buffer
	if err := g.WriteMermaid(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "flowchart LR") {
		t.Error("missing flowchart header")
	}
	if !strings.Contains(out, "group_project_a") {
		t.Error("missing project-a node")
	}
	if !strings.Contains(out, "|trigger|") {
		t.Error("missing trigger edge label")
	}
}

func TestExtractTriggerProject(t *testing.T) {
	tests := []struct {
		name    string
		trigger map[string]any
		want    string
	}{
		{
			name:    "direct project",
			trigger: map[string]any{"project": "group/proj"},
			want:    "group/proj",
		},
		{
			name:    "include with project",
			trigger: map[string]any{"include": map[string]any{"project": "group/proj"}},
			want:    "group/proj",
		},
		{
			name:    "include list",
			trigger: map[string]any{"include": []any{map[string]any{"project": "group/proj"}}},
			want:    "group/proj",
		},
		{
			name:    "no project",
			trigger: map[string]any{"strategy": "depend"},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTriggerProject(tt.trigger)
			if got != tt.want {
				t.Errorf("extractTriggerProject() = %q, want %q", got, tt.want)
			}
		})
	}
}
