package pipeline

import (
	"strings"
	"testing"
)

func TestParse_ComponentIncludeInputs(t *testing.T) {
	yaml := `
include:
  - component: my/component@1.0.0
    inputs:
      VAR: "value"
      LIST: [a, b]
job:
  script: ["echo hi"]
`
	doc, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Includes) != 1 {
		t.Fatalf("expected 1 include, got %d", len(doc.Includes))
	}
	inc := doc.Includes[0]
	if inc.Type != IncludeComponent {
		t.Fatalf("expected include type component, got %v", inc.Type)
	}
	if inc.Component != "my/component@1.0.0" {
		t.Fatalf("unexpected component value: %q", inc.Component)
	}
	if inc.Inputs == nil {
		t.Fatalf("expected inputs to be captured, got nil")
	}
	if v, ok := inc.Inputs["VAR"].(string); !ok || v != "value" {
		t.Fatalf("expected inputs.VAR=\"value\", got %#v", inc.Inputs["VAR"])
	}
	lst, ok := inc.Inputs["LIST"].([]any)
	if !ok || len(lst) != 2 {
		t.Fatalf("expected inputs.LIST length 2, got %#v", inc.Inputs["LIST"])
	}
}
