package analyze

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const testDefaultRecommendation = "Review and harden configuration; apply least privilege and restrict triggers/inputs."

// --- SCRIPT_INJECTION_RISK tests ---

func TestScriptInjectionRisk_LocalScriptInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{"./scripts/deploy.sh"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_BashScriptInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"bash scripts/test.sh"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_MakeInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"make deploy"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_PythonScriptInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "lint",
			Script: []string{"python scripts/lint.py"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding for python script, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_SourceInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "setup",
			Script: []string{"source .envrc"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding for source command, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_NonMRJob_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{"./scripts/deploy.sh"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("did not expect SCRIPT_INJECTION_RISK for non-MR job, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_InlineScript_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"echo hello", "go test ./...", "apt-get install -y curl"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, ScriptInjectionRiskID) {
		t.Fatalf("did not expect SCRIPT_INJECTION_RISK for inline commands, got: %+v", findings)
	}
}

func TestScriptInjectionRisk_WithForkProtection_MediumSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"make build"},
			Rules: []any{
				map[string]any{
					"if": "$CI_PIPELINE_SOURCE == 'merge_request_event' && $CI_MERGE_REQUEST_SOURCE_PROJECT_PATH == $CI_MERGE_REQUEST_TARGET_PROJECT_PATH",
				},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var found *Finding
	for i, f := range findings {
		if f.ID == ScriptInjectionRiskID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding")
		return
	}
	if found.Severity != SeverityMedium {
		t.Fatalf("expected MEDIUM severity with fork protection, got: %v", found.Severity)
	}
}

func TestScriptInjectionRisk_HighSeverity_NoProtection(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{"./scripts/deploy.sh"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var found *Finding
	for i, f := range findings {
		if f.ID == ScriptInjectionRiskID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected SCRIPT_INJECTION_RISK finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity without fork protection, got: %v", found.Severity)
	}
}

// --- SELF_MERGE_POSSIBLE tests ---

func TestSelfMergePossible_MRJobWithoutProtection(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"go test ./..."},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, SelfMergePossibleID) {
		t.Fatalf("expected SELF_MERGE_POSSIBLE finding, got: %+v", findings)
	}
}

func TestSelfMergePossible_WithApprovalRules_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"go test ./..."},
			Rules: []any{
				map[string]any{
					"if": "$CI_PIPELINE_SOURCE == 'merge_request_event' && $CI_MERGE_REQUEST_APPROVED == 'true'",
				},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, SelfMergePossibleID) {
		t.Fatalf("did not expect SELF_MERGE_POSSIBLE with approval rules, got: %+v", findings)
	}
}

func TestSelfMergePossible_WithProtectedBranch_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{"deploy.sh"},
			Rules: []any{
				map[string]any{
					"if": "$CI_PIPELINE_SOURCE == 'merge_request_event' && $CI_COMMIT_REF_PROTECTED == 'true'",
				},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, SelfMergePossibleID) {
		t.Fatalf("did not expect SELF_MERGE_POSSIBLE with protected branch rule, got: %+v", findings)
	}
}

func TestSelfMergePossible_NoMRJobs_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"make build"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, SelfMergePossibleID) {
		t.Fatalf("did not expect SELF_MERGE_POSSIBLE without MR jobs, got: %+v", findings)
	}
}

func TestSelfMergePossible_HighSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"echo test"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var found *Finding
	for i, f := range findings {
		if f.ID == SelfMergePossibleID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected SELF_MERGE_POSSIBLE finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got: %v", found.Severity)
	}
}

func TestSelfMergePossible_WorkflowProtection_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Workflow: pipeline.Workflow{
			Rules: []any{
				map[string]any{
					"if": "$CI_COMMIT_REF_PROTECTED == 'true'",
				},
			},
		},
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"echo test"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, SelfMergePossibleID) {
		t.Fatalf("did not expect SELF_MERGE_POSSIBLE with workflow-level protection, got: %+v", findings)
	}
}

// --- CACHE_POISONING_RISK tests ---

func TestCachePoisoningRisk_PushPolicy(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"npm install"},
			Cache: map[string]any{
				"key":    "node-modules",
				"paths":  []any{"node_modules/"},
				"policy": "push",
			},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, CachePoisoningRiskID) {
		t.Fatalf("expected CACHE_POISONING_RISK finding, got: %+v", findings)
	}
}

func TestCachePoisoningRisk_PullPushPolicy(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"pip install -r requirements.txt"},
			Cache: map[string]any{
				"key":    "pip-cache",
				"paths":  []any{".cache/pip"},
				"policy": "pull-push",
			},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, CachePoisoningRiskID) {
		t.Fatalf("expected CACHE_POISONING_RISK finding for pull-push policy, got: %+v", findings)
	}
}

func TestCachePoisoningRisk_PullOnlyPolicy_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"npm test"},
			Cache: map[string]any{
				"key":    "node-modules",
				"paths":  []any{"node_modules/"},
				"policy": "pull",
			},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, CachePoisoningRiskID) {
		t.Fatalf("did not expect CACHE_POISONING_RISK for pull-only policy, got: %+v", findings)
	}
}

func TestCachePoisoningRisk_NonMRJob_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"npm install"},
			Cache: map[string]any{
				"key":    "node-modules",
				"paths":  []any{"node_modules/"},
				"policy": "push",
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, CachePoisoningRiskID) {
		t.Fatalf("did not expect CACHE_POISONING_RISK for non-MR job, got: %+v", findings)
	}
}

func TestCachePoisoningRisk_NoCacheConfig_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"go test ./..."},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, CachePoisoningRiskID) {
		t.Fatalf("did not expect CACHE_POISONING_RISK without cache config, got: %+v", findings)
	}
}

func TestCachePoisoningRisk_WithForkProtection_MediumSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"npm install"},
			Cache: map[string]any{
				"key":    "node-modules",
				"paths":  []any{"node_modules/"},
				"policy": "push",
			},
			Rules: []any{
				map[string]any{
					"if": "$CI_PIPELINE_SOURCE == 'merge_request_event' && $CI_MERGE_REQUEST_SOURCE_PROJECT_PATH == $CI_MERGE_REQUEST_TARGET_PROJECT_PATH",
				},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var found *Finding
	for i, f := range findings {
		if f.ID == CachePoisoningRiskID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected CACHE_POISONING_RISK finding")
	}
	if found.Severity != SeverityMedium {
		t.Fatalf("expected MEDIUM severity with fork protection, got: %v", found.Severity)
	}
}

func TestCachePoisoningRisk_NoForkProtection_HighSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"npm install"},
			Cache: map[string]any{
				"key":    "node-modules",
				"paths":  []any{"node_modules/"},
				"policy": "push",
			},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var found *Finding
	for i, f := range findings {
		if f.ID == CachePoisoningRiskID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected CACHE_POISONING_RISK finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity without fork protection, got: %v", found.Severity)
	}
}

// --- Helper function tests ---

func TestIsExternalScriptExecution(t *testing.T) {
	tests := []struct {
		line   string
		expect bool
	}{
		{"./scripts/deploy.sh", true},
		{"bash scripts/test.sh", true},
		{"sh ci/lint.sh", true},
		{"python scripts/lint.py", true},
		{"python3 tools/check.py", true},
		{"make deploy", true},
		{"source .envrc", true},
		{". .envrc", true},
		{"./gradlew build", true},
		{".\\build.ps1", true},
		{"node scripts/build.js", true},
		{"ruby scripts/check.rb", true},
		{"scripts/run.sh", true},
		{"echo hello", false},
		{"go test ./...", false},
		{"apt-get install -y curl", false},
		{"ls -la", false},
		{"pip install flask", false},
		{"bash -c 'echo hello'", false},
		{"python -m pytest", false},
	}
	for _, tt := range tests {
		got := isExternalScriptExecution(tt.line)
		if got != tt.expect {
			t.Errorf("isExternalScriptExecution(%q) = %v, want %v", tt.line, got, tt.expect)
		}
	}
}

func TestExtractCachePolicy(t *testing.T) {
	tests := []struct {
		name   string
		cache  map[string]any
		expect string
	}{
		{"push policy", map[string]any{"policy": "push"}, "push"},
		{"pull-push policy", map[string]any{"policy": "pull-push"}, "pull-push"},
		{"pull policy", map[string]any{"policy": "pull"}, "pull"},
		{"no policy", map[string]any{"key": "test"}, ""},
		{"non-string policy", map[string]any{"policy": 123}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCachePolicy(tt.cache)
			if got != tt.expect {
				t.Errorf("extractCachePolicy() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestWithRecommendations_NewFindings(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantSub string
	}{
		{"script injection risk", ScriptInjectionRiskID, "repo-local scripts"},
		{"self merge possible", SelfMergePossibleID, "approvals"},
		{"cache poisoning risk", CachePoisoningRiskID, "cache policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []Finding{{ID: tt.id, Severity: SeverityMedium, Title: "test"}}
			out := withRecommendations(in)
			if out[0].Recommendation == "" {
				t.Fatalf("expected non-empty recommendation for %s", tt.id)
			}
			if out[0].Recommendation == testDefaultRecommendation {
				t.Fatalf("got default recommendation for %s, expected specific", tt.id)
			}
			if !strings.Contains(out[0].Recommendation, tt.wantSub) {
				t.Fatalf("recommendation for %s missing expected substring %q, got: %s", tt.id, tt.wantSub, out[0].Recommendation)
			}
		})
	}
}
