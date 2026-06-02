package pipeline

import (
	"strings"
	"testing"
)

func TestParse_IncludesVariants(t *testing.T) {
	yaml := `
include:
  - local: ".gitlab/ci/common.yml"
  - project: "group/project"
    file: ["/ci/pipeline.yml", "ci/common.yml"]
    ref: "v1.2.3"
  - remote: "https://example.com/ci.yml"
  - template: "Security/Secret-Detection.gitlab-ci.yml"
  - component: "acme/build@1.0.0"
`
	doc, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	incs := doc.Includes
	if len(incs) != 5 {
		t.Fatalf("expected 5 includes, got %d: %#v", len(incs), incs)
	}
	if incs[0].Type != IncludeLocal || incs[0].Local == "" {
		t.Fatalf("expected first include to be local with path, got %#v", incs[0])
	}
	if incs[1].Type != IncludeProject || incs[1].Project != "group/project" || len(incs[1].File) != 2 || incs[1].Ref != "v1.2.3" {
		t.Fatalf("unexpected project include: %#v", incs[1])
	}
	if incs[2].Type != IncludeRemote || incs[2].Remote == "" {
		t.Fatalf("unexpected remote include: %#v", incs[2])
	}
	if incs[3].Type != IncludeTemplate || incs[3].Template == "" {
		t.Fatalf("unexpected template include: %#v", incs[3])
	}
	if incs[4].Type != IncludeComponent || incs[4].Component == "" {
		t.Fatalf("unexpected component include: %#v", incs[4])
	}
}
