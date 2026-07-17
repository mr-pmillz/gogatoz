package analyze

import "testing"

func TestDetectNeedsProjectRisk(t *testing.T) {
	tests := []severityTestCase{
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

	runSeverityDetectionTests(t, tests, NeedsProjectRiskID, detectNeedsProjectRisk)
}
