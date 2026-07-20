package analyze

import "testing"

func TestDetectTriggerArtifactRisk(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "artifact trigger - MR triggered - HIGH",
			yaml: `
generate:
  script:
    - echo "build"
  artifacts:
    paths:
      - child.yml

deploy:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  trigger:
    include:
      - artifact: child.yml
        job: generate
    strategy: depend
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "project trigger without artifact - no finding",
			yaml: `
deploy:
  trigger:
    project: other/project
    branch: main
`,
			wantFound: false,
		},
		{
			name: "artifact trigger - no rules - MEDIUM",
			yaml: `
deploy:
  trigger:
    include:
      - artifact: dynamic.yml
        job: gen
`,
			wantFound: true,
			wantHigh:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectTriggerArtifactRisk(doc)
			found := hasFindingID(findings, TriggerArtifactRiskID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
			if tc.wantHigh && found {
				for _, f := range findings {
					if f.ID == TriggerArtifactRiskID && f.Severity != SeverityHigh {
						t.Errorf("severity=%s want=HIGH", f.Severity)
					}
				}
			}
		})
	}
}
