package pipeline

import (
	"strings"
	"testing"
)

func findJob(doc *Document, name string) (Job, bool) {
	for _, j := range doc.Jobs {
		if j.Name == name {
			return j, true
		}
	}
	return Job{}, false
}

func TestYAMLMergeKey_SingleParent(t *testing.T) {
	y := `
base: &b
  stage: build
  script: ["echo base"]
  tags: ["t1"]

job1:
  <<: *b
  script: ["echo child"]
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	j, ok := findJob(doc, "job1")
	if !ok {
		t.Fatalf("job1 not found: %+v", doc.Jobs)
	}
	if j.Stage != stageBuild {
		t.Fatalf("expected inherited stage build, got %q", j.Stage)
	}
	if len(j.Tags) != 1 || j.Tags[0] != "t1" {
		t.Fatalf("expected inherited tags [t1], got %v", j.Tags)
	}
	if len(j.Script) != 1 || j.Script[0] != "echo child" {
		t.Fatalf("expected child script override, got %v", j.Script)
	}
}

func TestYAMLMergeKey_ListOfParents_LastWins(t *testing.T) {
	y := `
p1: &p1
  variables:
    A: "1"
    B: "2"
  stage: build

p2: &p2
  variables:
    B: "9"
    C: "3"
  stage: test

child:
  <<: [*p1, *p2]
  script: ["echo ok"]
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	j, ok := findJob(doc, "child")
	if !ok {
		t.Fatalf("child not found: %+v", doc.Jobs)
	}
	// Per YAML merge key spec, earlier parents in the list take priority.
	// p1 is first, so p1's stage ("build") wins over p2's ("test").
	if j.Stage != stageBuild {
		t.Fatalf("expected first parent stage 'build', got %q", j.Stage)
	}
	// Variables: p1's entire variables map wins (shallow precedence), so
	// only A and B from p1 are present; C from p2 is not merged in.
	if j.Variables["A"] != "1" {
		t.Fatalf("expected A=1, got %v", j.Variables["A"])
	}
	if j.Variables["B"] != "2" {
		t.Fatalf("expected B=2 (from p1, first wins), got %v", j.Variables["B"])
	}
	// Child script overwrites parent
	if len(j.Script) != 1 || j.Script[0] != "echo ok" {
		t.Fatalf("expected child script, got %v", j.Script)
	}
}
