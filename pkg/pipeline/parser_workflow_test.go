package pipeline

import (
	"strings"
	"testing"
)

func TestParse_WorkflowRulesAndTopScripts(t *testing.T) {
	yaml := `
workflow:
  name: ci
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: always
before_script:
  - echo before
after_script:
  - echo after
job:
  script: ["echo hi"]
`
	doc, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if doc.Workflow.Name != "ci" || doc.Workflow.Rules == nil {
		t.Fatalf("expected workflow name+rules, got: %#v", doc.Workflow)
	}
	if len(doc.BeforeScript) != 1 || len(doc.AfterScript) != 1 {
		t.Fatalf("expected before/after_script captured, got before=%v after=%v", doc.BeforeScript, doc.AfterScript)
	}
}
