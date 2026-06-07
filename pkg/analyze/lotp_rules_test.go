package analyze

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// helper: parse a YAML string into a Document for testing.
func mustParseDoc(t *testing.T, yaml string) *pipeline.Document {
	t.Helper()
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return doc
}

// --- LOTP_TOOL_EXEC ---

func TestDetectLOTPToolExec(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantID    string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "npm in MR-triggered job - MEDIUM (shared runner)",
			yaml: `
lint:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - npm install
    - npm run lint
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "make in MR-triggered job with self-hosted runner - HIGH",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  tags: [shell_executor]
  script:
    - make test
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "pip install in before_script - MEDIUM (before_script coverage)",
			yaml: `
test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - pip install -r requirements.txt
  script:
    - echo "run tests"
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "npm in fork-protected MR job - downgraded to LOW",
			yaml: `
lint:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_SOURCE_PROJECT_PATH == $CI_MERGE_REQUEST_TARGET_PROJECT_PATH
  script:
    - npm install
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "npm only on protected branches - not flagged",
			yaml: `
lint:
  only:
    - main
    - /^release\/.*/
  script:
    - npm install
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: false,
		},
		{
			name: "no LOTP tool - not flagged",
			yaml: `
echo_job:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - echo "hello world"
    - cat file.txt
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: false,
		},
		{
			name: "gradle in MR-triggered job - MEDIUM",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./gradlew build
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: true,
		},
		{
			name: "pytest in after_script - covered by effectiveScripts",
			yaml: `
test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - echo running
  after_script:
    - pytest tests/
`,
			wantID:    "LOTP_TOOL_EXEC",
			wantFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectLOTPToolExec(doc)
			found := hasFindingID(findings, tc.wantID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%v", found, tc.wantFound, findings)
			}
			if tc.wantFound && tc.wantHigh {
				var gotHigh bool
				for _, f := range findings {
					if f.ID == tc.wantID && f.Severity == SeverityHigh {
						gotHigh = true
					}
				}
				if !gotHigh {
					t.Errorf("expected HIGH severity but got: %v", findings)
				}
			}
		})
	}
}

// --- CACHE_KEY_INJECTION ---

func TestDetectCacheKeyInjection(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "cache key uses CI_MERGE_REQUEST_TITLE - HIGH (MR-triggered)",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key: $CI_MERGE_REQUEST_TITLE
    paths: [.cache/]
  script: [echo ok]
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "cache key uses attacker variable in prefix - HIGH",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key:
      files: [package.json]
      prefix: $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
    paths: [node_modules/]
  script: [npm install]
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "cache key is static string - not flagged",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key: my-static-key
    paths: [.cache/]
  script: [echo ok]
`,
			wantFound: false,
		},
		{
			name: "cache key uses safe variable - not flagged",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key: $CI_JOB_NAME
    paths: [.cache/]
  script: [echo ok]
`,
			wantFound: false,
		},
		{
			name: "attacker variable in cache key on non-MR job - MEDIUM",
			yaml: `
build:
  script: [echo ok]
  cache:
    key: $CI_COMMIT_MESSAGE
    paths: [.cache/]
`,
			wantFound: true,
			wantHigh:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectCacheKeyInjection(doc)
			found := hasFindingID(findings, "CACHE_KEY_INJECTION")
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%v", found, tc.wantFound, findings)
			}
			if tc.wantFound && tc.wantHigh {
				var gotHigh bool
				for _, f := range findings {
					if f.ID == "CACHE_KEY_INJECTION" && f.Severity == SeverityHigh {
						gotHigh = true
					}
				}
				if !gotHigh {
					t.Errorf("expected HIGH but got: %v", findings)
				}
			}
		})
	}
}

// --- OIDC_TOKEN_MR_RISK ---

func TestDetectOIDCTokenMRRisk(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
	}{
		{
			name: "id_tokens in MR-triggered job - flagged",
			yaml: `
deploy:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts assume-role-with-web-identity
`,
			wantFound: true,
		},
		{
			name: "id_tokens on protected branch only - not flagged",
			yaml: `
deploy:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts assume-role-with-web-identity
`,
			wantFound: false,
		},
		{
			name: "no id_tokens - not flagged",
			yaml: `
deploy:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - echo deploy
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectOIDCTokenMRRisk(doc)
			found := hasFindingID(findings, "OIDC_TOKEN_MR_RISK")
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%v", found, tc.wantFound, findings)
			}
		})
	}
}

// --- TRIGGER_CHAIN_RISK ---

func TestDetectTriggerChainRisk(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
		wantHigh  bool
	}{
		{
			name: "trigger in MR-triggered job - MEDIUM",
			yaml: `
deploy_child:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  trigger:
    project: group/child-project
`,
			wantFound: true,
			wantHigh:  false,
		},
		{
			name: "trigger with strategy:depend in MR job - HIGH",
			yaml: `
deploy_child:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  trigger:
    project: group/child-project
    strategy: depend
`,
			wantFound: true,
			wantHigh:  true,
		},
		{
			name: "trigger on protected branch only - not flagged",
			yaml: `
deploy_child:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  trigger:
    project: group/child-project
`,
			wantFound: false,
		},
		{
			name: "no trigger - not flagged",
			yaml: `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - make build
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectTriggerChainRisk(doc)
			found := hasFindingID(findings, "TRIGGER_CHAIN_RISK")
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%v", found, tc.wantFound, findings)
			}
			if tc.wantFound && tc.wantHigh {
				var gotHigh bool
				for _, f := range findings {
					if f.ID == "TRIGGER_CHAIN_RISK" && f.Severity == SeverityHigh {
						gotHigh = true
					}
				}
				if !gotHigh {
					t.Errorf("expected HIGH but got: %v", findings)
				}
			}
		})
	}
}

// --- DetectLOTPTools unit tests ---

func TestDetectLOTPTools(t *testing.T) {
	tests := []struct {
		name    string
		scripts []string
		want    []string // expected tool Names
	}{
		{
			name:    "npm install detected",
			scripts: []string{"npm install", "npm run test"},
			want:    []string{"npm"},
		},
		{
			name:    "make detected at start of line",
			scripts: []string{"make build ARGS=foo"},
			want:    []string{"make"},
		},
		{
			name:    "make not detected mid-line",
			scripts: []string{"echo 'run make'"},
			want:    nil,
		},
		{
			name:    "multiple tools in different script lines",
			scripts: []string{"pip install -r requirements.txt", "pytest tests/"},
			want:    []string{"pip", "pytest"},
		},
		{
			name:    "gradlew detected",
			scripts: []string{"./gradlew build"},
			want:    []string{"gradle"},
		},
		{
			name:    "no LOTP tool - empty result",
			scripts: []string{"echo hello", "cat file.txt", "ls -la"},
			want:    nil,
		},
		{
			name:    "terraform detected",
			scripts: []string{"terraform plan -out=tfplan"},
			want:    []string{"terraform"},
		},
		{
			name:    "golangci-lint detected",
			scripts: []string{"golangci-lint run ./..."},
			want:    []string{"golangci-lint"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectLOTPTools(tc.scripts)
			gotNames := make(map[string]bool)
			for _, t := range got {
				gotNames[t.Name] = true
			}
			for _, w := range tc.want {
				if !gotNames[w] {
					t.Errorf("expected tool %q not found in %v", w, got)
				}
			}
			if len(tc.want) == 0 && len(got) != 0 {
				t.Errorf("expected no tools but got: %v", got)
			}
		})
	}
}

// --- effectiveScripts tests ---

func TestEffectiveScripts(t *testing.T) {
	doc := &pipeline.Document{
		BeforeScript: []string{"global-before"},
		AfterScript:  []string{"global-after"},
	}

	t.Run("job with no before/after uses global", func(t *testing.T) {
		job := pipeline.Job{Script: []string{"main-script"}}
		got := effectiveScripts(job, doc)
		want := []string{"global-before", "main-script", "global-after"}
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for i, g := range got {
			if g != want[i] {
				t.Errorf("[%d] got %q want %q", i, g, want[i])
			}
		}
	})

	t.Run("job-level before_script overrides global", func(t *testing.T) {
		job := pipeline.Job{
			BeforeScript: []string{"job-before"},
			Script:       []string{"main-script"},
		}
		got := effectiveScripts(job, doc)
		want := []string{"job-before", "main-script", "global-after"}
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for i, g := range got {
			if g != want[i] {
				t.Errorf("[%d] got %q want %q", i, g, want[i])
			}
		}
	})

	t.Run("injection in before_script is detected via VARIABLE_INJECTION", func(t *testing.T) {
		yaml := `
test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - make $CI_MERGE_REQUEST_TITLE
  script:
    - echo done
`
		d := mustParseDoc(t, yaml)
		findings := detectVariableInjection(d)
		if !hasFindingID(findings, "VARIABLE_INJECTION") {
			t.Errorf("expected VARIABLE_INJECTION for unsafe var in before_script; got %v", findings)
		}
	})
}
