package scriptinject

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestExtractScriptRefs_BasicPatterns(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantRefs []string
	}{
		{
			name: "bash script reference",
			yaml: `
build:
  stage: build
  script:
    - bash scripts/build.sh
    - echo "done"
`,
			wantRefs: []string{"scripts/build.sh"},
		},
		{
			name: "dot-slash script",
			yaml: `
test:
  stage: test
  script:
    - ./scripts/run-tests.sh
`,
			wantRefs: []string{"scripts/run-tests.sh"},
		},
		{
			name: "sh command",
			yaml: `
deploy:
  script:
    - sh deploy/run.sh --env prod
`,
			wantRefs: []string{"deploy/run.sh"},
		},
		{
			name: "python script",
			yaml: `
lint:
  script:
    - python3 scripts/lint.py
    - python tools/check.py --strict
`,
			wantRefs: []string{"scripts/lint.py", "tools/check.py"},
		},
		{
			name: "source command",
			yaml: `
setup:
  script:
    - source scripts/env.sh
    - . ./tools/helpers.sh
`,
			wantRefs: []string{"scripts/env.sh", "tools/helpers.sh"},
		},
		{
			name: "make reference implies Makefile",
			yaml: `
build:
  script:
    - make build
`,
			wantRefs: []string{"Makefile"},
		},
		{
			name: "node script",
			yaml: `
test:
  script:
    - node scripts/test.js
`,
			wantRefs: []string{"scripts/test.js"},
		},
		{
			name: "no script references",
			yaml: `
echo-job:
  script:
    - echo "hello world"
    - apt-get update
`,
			wantRefs: nil,
		},
		{
			name: "chmod then execute",
			yaml: `
run:
  script:
    - chmod +x scripts/deploy.sh
    - scripts/deploy.sh
`,
			wantRefs: []string{"scripts/deploy.sh"},
		},
		{
			name: "dedup same file from multiple lines",
			yaml: `
run:
  script:
    - bash scripts/build.sh
    - bash scripts/build.sh --clean
`,
			wantRefs: []string{"scripts/build.sh"},
		},
		{
			name: "ruby script",
			yaml: `
test:
  script:
    - ruby scripts/test.rb
`,
			wantRefs: []string{"scripts/test.rb"},
		},
		{
			name: "perl script",
			yaml: `
check:
  script:
    - perl scripts/check.pl
`,
			wantRefs: []string{"scripts/check.pl"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := pipeline.Parse(strings.NewReader(tt.yaml))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			refs := ExtractScriptRefs(doc)
			if tt.wantRefs == nil {
				if len(refs) != 0 {
					t.Fatalf("expected no refs, got %v", refs)
				}
				return
			}
			if len(refs) != len(tt.wantRefs) {
				t.Fatalf("expected %d refs, got %d: %v", len(tt.wantRefs), len(refs), refs)
			}
			for i, want := range tt.wantRefs {
				if refs[i].Path != want {
					t.Errorf("ref[%d]: expected %s, got %s", i, want, refs[i].Path)
				}
			}
		})
	}
}

func TestExtractScriptRefs_JobContext(t *testing.T) {
	yaml := `
build:
  script:
    - bash scripts/build.sh
deploy:
  script:
    - ./scripts/deploy.sh
`
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	refs := ExtractScriptRefs(doc)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(refs), refs)
	}
	// Check job names are tracked
	jobs := map[string]bool{}
	for _, r := range refs {
		jobs[r.JobName] = true
	}
	if !jobs["build"] || !jobs["deploy"] {
		t.Fatalf("expected build and deploy jobs, got %v", jobs)
	}
}
