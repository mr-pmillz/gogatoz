package pipeline

import (
	"strings"
	"testing"
)

func TestParse_JobExtendsVariants(t *testing.T) {
	yaml := `
job1:
  script: ["echo hi"]
  extends: base
job2:
  script:
    - echo ok
  extends: [base, other]
base:
  script: ["echo base"]
`
	doc, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Jobs) != 3 {
		t.Fatalf("expected 3 jobs, got %d", len(doc.Jobs))
	}
	var j1, j2 Job
	for _, j := range doc.Jobs {
		if j.Name == "job1" {
			j1 = j
		}
		if j.Name == "job2" {
			j2 = j
		}
	}
	if len(j1.Extends) != 1 || j1.Extends[0] != "base" {
		t.Fatalf("job1 extends expected [base], got %#v", j1.Extends)
	}
	if len(j2.Extends) != 2 || j2.Extends[0] != "base" || j2.Extends[1] != "other" {
		t.Fatalf("job2 extends expected [base other], got %#v", j2.Extends)
	}
}
