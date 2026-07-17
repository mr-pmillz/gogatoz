package analyze

import "testing"

func TestDetectNeedsProjectRisk(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "MR-triggered cross-project needs - HIGH",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  needs:
    - project: external/lib
      job: package
      ref: main
      artifacts: true
  script:
    - echo "using external artifacts"
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "non-MR cross-project needs - MEDIUM",
			yaml: `
build:
  needs:
    - project: shared/utils
      job: build
      ref: v1.0.0
      artifacts: true
  script:
    - echo "using external artifacts"
`,
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "same-project needs - no finding",
			yaml: `
test:
  needs:
    - job: build
      artifacts: true
  script:
    - echo "testing"
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectNeedsProjectRisk(doc)
			found := hasFindingID(findings, NeedsProjectRiskID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
			if tc.wantHigh && found {
				for _, f := range findings {
					if f.ID == NeedsProjectRiskID && f.Severity != SeverityHigh {
						t.Errorf("severity=%s want=HIGH", f.Severity)
					}
				}
			}
		})
	}
}
