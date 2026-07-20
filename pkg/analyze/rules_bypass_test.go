package analyze

import "testing"

func TestDetectRulesSecurityBypass(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
	}{
		{
			name: "restrictive changes on sast - finding",
			yaml: `
sast:
  rules:
    - changes:
        - "nonexistent-path/**/*"
  script:
    - echo "sast scan"
`,
			wantFound: true,
		},
		{
			name: "normal sast - no finding",
			yaml: `
sast:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - semgrep --config auto .
`,
			wantFound: false,
		},
		{
			name: "nonexistent exists on secret-detection - finding",
			yaml: `
secret-detection:
  rules:
    - exists:
        - "nonexistent-sentinel-file"
  script:
    - gitleaks detect
`,
			wantFound: true,
		},
		{
			name: "non-security job with restrictive rules - no finding",
			yaml: `
build:
  rules:
    - changes:
        - "nonexistent-path/**/*"
  script:
    - make build
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectRulesSecurityBypass(doc)
			found := hasFindingID(findings, RulesSecurityBypassID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
		})
	}
}
