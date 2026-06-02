package pipeline

import (
	"strings"
	"testing"
)

// TestApplyMerge_NestedMapMerge verifies that the YAML merge key (<<) propagates
// parent map fields to the child when the child does not override them.
// Note: YAML merge key is a shallow merge — if the child explicitly sets a key
// like `variables`, the child's value replaces the parent's entirely.
func TestApplyMerge_NestedMapMerge(t *testing.T) {
	y := `
defaults: &defaults
  variables:
    TIMEOUT: "30"
    RETRIES: "3"
  tags: ["shared"]
  stage: build

job1:
  <<: *defaults
  script: ["echo ok"]
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	j, ok := findJob(doc, "job1")
	if !ok {
		t.Fatalf("job1 not found: %+v", doc.Jobs)
	}
	// Variables should be inherited fully (child has no variables key)
	if j.Variables["TIMEOUT"] != "30" {
		t.Fatalf("expected TIMEOUT=30 (from parent), got %v", j.Variables["TIMEOUT"])
	}
	if j.Variables["RETRIES"] != "3" {
		t.Fatalf("expected RETRIES=3 (from parent), got %v", j.Variables["RETRIES"])
	}
	// Tags should be inherited
	if len(j.Tags) != 1 || j.Tags[0] != "shared" {
		t.Fatalf("expected tags [shared], got %v", j.Tags)
	}
	// Stage should be inherited
	if j.Stage != stageBuild {
		t.Fatalf("expected stage build from parent, got %q", j.Stage)
	}
	// Script is child's own
	if len(j.Script) != 1 || j.Script[0] != "echo ok" {
		t.Fatalf("expected script [echo ok], got %v", j.Script)
	}
}

// TestApplyExtends_CycleDetection verifies that a cycle in extends does not cause
// infinite recursion or panic — it should return a stable result.
func TestApplyExtends_CycleDetection(t *testing.T) {
	y := `
jobA:
  extends: jobB
  script: ["echo A"]
  stage: build

jobB:
  extends: jobA
  script: ["echo B"]
  stage: test
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Should not panic; both jobs should exist
	_, okA := findJob(doc, "jobA")
	_, okB := findJob(doc, "jobB")
	if !okA {
		t.Fatal("jobA not found after cycle resolution")
	}
	if !okB {
		t.Fatal("jobB not found after cycle resolution")
	}
}

// TestApplyExtends_DeepChain verifies that a deep extends chain (C extends B extends A)
// propagates all ancestor fields correctly.
func TestApplyExtends_DeepChain(t *testing.T) {
	y := `
grandparent:
  image: alpine:3.18
  variables:
    ENV: "production"
  tags: ["gpu"]

parent:
  extends: grandparent
  stage: build
  variables:
    DEBUG: "false"

child:
  extends: parent
  script: ["echo child"]
  variables:
    APP: "myapp"
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	child, ok := findJob(doc, "child")
	if !ok {
		t.Fatalf("child not found: %+v", doc.Jobs)
	}
	// Should inherit image from grandparent
	if child.Image != "alpine:3.18" {
		t.Fatalf("expected image alpine:3.18 from grandparent, got %q", child.Image)
	}
	// Should inherit stage from parent
	if child.Stage != stageBuild {
		t.Fatalf("expected stage build from parent, got %q", child.Stage)
	}
	// Should inherit tags from grandparent
	if len(child.Tags) != 1 || child.Tags[0] != "gpu" {
		t.Fatalf("expected tags [gpu] from grandparent, got %v", child.Tags)
	}
	// Variables should merge from all ancestors
	if child.Variables["ENV"] != "production" {
		t.Fatalf("expected ENV=production from grandparent, got %v", child.Variables["ENV"])
	}
	if child.Variables["DEBUG"] != "false" {
		t.Fatalf("expected DEBUG=false from parent, got %v", child.Variables["DEBUG"])
	}
	if child.Variables["APP"] != "myapp" {
		t.Fatalf("expected APP=myapp from child, got %v", child.Variables["APP"])
	}
}

// TestMergeJob_AllFields verifies that jobFromMap + extends correctly merges
// overlapping fields from two jobs — maps merged, scalars/arrays overridden by child.
func TestMergeJob_AllFields(t *testing.T) {
	y := `
base:
  image: golang:1.22
  stage: build
  variables:
    GO111MODULE: "on"
    GOFLAGS: "-v"
  tags: ["runner1"]
  script: ["go build"]
  when: on_success
  allow_failure: false
  services:
    - postgres:15
  artifacts:
    paths: ["bin/"]

child:
  extends: base
  image: golang:1.23
  variables:
    GOFLAGS: "-race"
    EXTRA: "yes"
  tags: ["runner2"]
  script: ["go test"]
  when: manual
  allow_failure: true
  services:
    - redis:7
`
	doc, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	child, ok := findJob(doc, "child")
	if !ok {
		t.Fatalf("child not found: %+v", doc.Jobs)
	}
	// Scalar fields: child wins
	if child.Image != "golang:1.23" {
		t.Fatalf("image: want golang:1.23, got %q", child.Image)
	}
	if child.Stage != stageBuild {
		t.Fatalf("stage: want build (from base), got %q", child.Stage)
	}
	if child.When != "manual" {
		t.Fatalf("when: want manual (from child), got %q", child.When)
	}
	if !child.AllowFailure {
		t.Fatal("allow_failure: want true (from child)")
	}
	// Map fields (variables): deep merged — child overrides, parent fills gaps
	if child.Variables["GO111MODULE"] != "on" {
		t.Fatalf("var GO111MODULE: want on (from base), got %v", child.Variables["GO111MODULE"])
	}
	if child.Variables["GOFLAGS"] != "-race" {
		t.Fatalf("var GOFLAGS: want -race (child wins), got %v", child.Variables["GOFLAGS"])
	}
	if child.Variables["EXTRA"] != "yes" {
		t.Fatalf("var EXTRA: want yes (child), got %v", child.Variables["EXTRA"])
	}
	// Array fields (script, tags, services): child overrides entirely
	if len(child.Script) != 1 || child.Script[0] != "go test" {
		t.Fatalf("script: want [go test], got %v", child.Script)
	}
	if len(child.Tags) != 1 || child.Tags[0] != "runner2" {
		t.Fatalf("tags: want [runner2], got %v", child.Tags)
	}
	if len(child.Services) != 1 || child.Services[0] != "redis:7" {
		t.Fatalf("services: want [redis:7], got %v", child.Services)
	}
	// Artifacts from base should be inherited since child has none
	if child.Artifacts == nil {
		t.Fatal("artifacts: expected inherited from base, got nil")
	}
}
