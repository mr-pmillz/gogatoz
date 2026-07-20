package analyze

import "testing"

func TestDetectArtifactReportInjection(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "SARIF without scanner - MR triggered - HIGH",
			yaml: `
override-sast:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - echo "generating clean report"
  artifacts:
    reports:
      sast: gl-sast-report.json
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "dep scanning without scanner - push triggered - MEDIUM",
			yaml: `
dep-override:
  script:
    - echo "no scanner here"
  artifacts:
    reports:
      dependency_scanning: gl-dep-report.json
`,
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "with real scanner - no finding",
			yaml: `
real-sast:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - semgrep --config auto .
  artifacts:
    reports:
      sast: gl-sast-report.json
`,
			wantFound: false,
		},
		{
			name: "no report artifact - no finding",
			yaml: `
normal-job:
  script:
    - echo "hello"
  artifacts:
    paths:
      - output.txt
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectArtifactReportInjection(doc)
			found := hasFindingID(findings, ArtifactReportInjectionID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
			if tc.wantHigh && found {
				for _, f := range findings {
					if f.ID == ArtifactReportInjectionID && f.Severity != SeverityHigh {
						t.Errorf("severity=%s want=HIGH", f.Severity)
					}
				}
			}
		})
	}
}
