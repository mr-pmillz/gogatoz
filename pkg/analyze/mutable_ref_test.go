package analyze

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectIncludeMutableRef(t *testing.T) {
	sha1 := strings.Repeat("a", 40)
	sha256 := strings.Repeat("b", 64)
	tests := []struct {
		name        string
		include     pipeline.Include
		wantMutable bool
	}{
		{
			name: "project release tag is mutable",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "infra/templates",
				Ref: "v1.2.3", File: []string{"/ci.yml"}},
			wantMutable: true,
		},
		{
			name: "project custom branch is mutable",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "infra/templates",
				Ref: "feature/new-pipeline", File: []string{"/ci.yml"}},
			wantMutable: true,
		},
		{
			name: "project short SHA is not immutable",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "infra/templates",
				Ref: "abc123def456", File: []string{"/ci.yml"}},
			wantMutable: true,
		},
		{
			name: "project full SHA-1 is immutable",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "infra/templates",
				Ref: sha1, File: []string{"/ci.yml"}},
		},
		{
			name: "project full SHA-256 is immutable",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "infra/templates",
				Ref: sha256, File: []string{"/ci.yml"}},
		},
		{
			name: "common branch remains branch-specific finding only",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "infra/templates",
				Ref: "main", File: []string{"/ci.yml"}},
		},
		{
			name:        "component release tag is mutable",
			include:     pipeline.Include{Type: pipeline.IncludeComponent, Component: "gitlab.example/infra/components/build@1.2.3"},
			wantMutable: true,
		},
		{
			name:    "component full SHA is immutable",
			include: pipeline.Include{Type: pipeline.IncludeComponent, Component: "gitlab.example/infra/components/build@" + sha1},
		},
		{
			name:        "component dynamic ref cannot prove immutability",
			include:     pipeline.Include{Type: pipeline.IncludeComponent, Component: "gitlab.example/infra/components/build@$COMPONENT_VERSION"},
			wantMutable: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := detectIncludeMutableRef(&pipeline.Document{Includes: []pipeline.Include{test.include}})
			if got := hasFindingID(findings, IncludeMutableRefID); got != test.wantMutable {
				t.Fatalf("mutable finding = %v, want %v; findings=%+v", got, test.wantMutable, findings)
			}
			if test.wantMutable {
				finding := findings[0]
				if finding.Severity != SeverityHigh {
					t.Errorf("severity = %s, want HIGH", finding.Severity)
				}
				if !strings.Contains(finding.Recommendation, "full commit SHA") {
					t.Errorf("recommendation = %q, want full commit SHA guidance", finding.Recommendation)
				}
			}
		})
	}
}

func TestRunIncludesMutableRefFinding(t *testing.T) {
	document := &pipeline.Document{Includes: []pipeline.Include{{
		Type: pipeline.IncludeProject, Project: "infra/templates", Ref: "v3.4.5", File: []string{"/build.yml"},
	}}}
	findings, err := Run(document)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, IncludeMutableRefID) {
		t.Fatalf("findings = %+v, want %s", findings, IncludeMutableRefID)
	}
}

func TestIsFullCommitSHA(t *testing.T) {
	for _, test := range []struct {
		ref  string
		want bool
	}{
		{strings.Repeat("a", 40), true},
		{strings.Repeat("A", 64), true},
		{strings.Repeat("f", 39), false},
		{"v1.2.3", false},
		{strings.Repeat("z", 40), false},
	} {
		if got := isFullCommitSHA(test.ref); got != test.want {
			t.Errorf("isFullCommitSHA(%q) = %v, want %v", test.ref, got, test.want)
		}
	}
}
