package pipeline

import (
	"strings"
	"testing"
)

func TestExtends_MergeSemantics_ParentsAndChildOverride(t *testing.T) {
	y := `
base: &b
  stage: build
  variables: {A: "1", B: "2"}
  tags: ["t1"]
  image: alpine:3.18
parent2: &p2
  stage: test
  variables: {B: "9", C: "3"}
child1:
  extends: base
  script: ["echo child1"]
child2:
  extends: [base, parent2]
  script: ["echo child2"]
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c1, ok := findJob(doc, "child1")
	if !ok {
		t.Fatalf("child1 not found")
	}
	if c1.Stage != stageBuild {
		t.Fatalf("child1 stage want build, got %q", c1.Stage)
	}
	if c1.Variables["A"] != "1" || c1.Variables["B"] != "2" {
		t.Fatalf("child1 vars unexpected: %v", c1.Variables)
	}
	if len(c1.Tags) != 1 || c1.Tags[0] != "t1" {
		t.Fatalf("child1 tags inherit failed: %v", c1.Tags)
	}
	if c1.Image != "alpine:3.18" {
		t.Fatalf("child1 image inherit failed: %q", c1.Image)
	}

	c2, ok := findJob(doc, "child2")
	if !ok {
		t.Fatalf("child2 not found")
	}
	if c2.Stage != "test" {
		t.Fatalf("child2 stage want test (last parent), got %q", c2.Stage)
	}
	if c2.Variables["A"] != "1" || c2.Variables["B"] != "9" || c2.Variables["C"] != "3" {
		t.Fatalf("child2 vars unexpected: %v", c2.Variables)
	}
	if len(c2.Tags) != 1 || c2.Tags[0] != "t1" {
		t.Fatalf("child2 tags inherit failed: %v", c2.Tags)
	}
}
