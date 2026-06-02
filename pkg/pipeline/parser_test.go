package pipeline

import (
	"strings"
	"testing"
)

func TestParse_DefaultAndScripts(t *testing.T) {
	yaml := `
stages: [build, test]
variables:
  FOO: bar
before_script:
  - echo pre
after_script: echo post
default:
  image: alpine:3.19
job1:
  stage: build
  script:
    - echo build
`
	doc, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if doc.Default == nil || doc.Default["image"] != "alpine:3.19" {
		t.Fatalf("expected default.image parsed, got %#v", doc.Default)
	}
	if len(doc.BeforeScript) != 1 || doc.BeforeScript[0] != "echo pre" {
		t.Fatalf("unexpected before_script: %#v", doc.BeforeScript)
	}
	if len(doc.AfterScript) != 1 || doc.AfterScript[0] != "echo post" {
		t.Fatalf("unexpected after_script: %#v", doc.AfterScript)
	}
	if len(doc.Jobs) != 1 || doc.Jobs[0].Name != "job1" {
		t.Fatalf("expected one job 'job1', got %#v", doc.Jobs)
	}
	// Ensure DebugString references new fields without panicking
	_ = doc.DebugString()
}
