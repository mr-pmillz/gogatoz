package analyze

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	VariableInjectionID = "VARIABLE_INJECTION"
	ForkMrUnprotectedID = "FORK_MR_UNPROTECTED"
	ArtifactPoisoningID = "ARTIFACT_POISONING_RISK"
)

func TestVariableInjection_MRTitleInScript(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"echo $CI_MERGE_REQUEST_TITLE"},
			Rules: map[string]any{
				"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'",
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, VariableInjectionID) {
		t.Fatalf("expected VARIABLE_INJECTION finding, got: %+v", findings)
	}
	// Should be HIGH severity since MR-triggered
	var found *Finding
	for i, f := range findings {
		if f.ID == VariableInjectionID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("VARIABLE_INJECTION finding not found")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for MR-triggered injection, got: %v", found.Severity)
	}
}

func TestVariableInjection_CommitMessageInSink(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"make release COMMIT_MSG=$CI_COMMIT_MESSAGE"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, VariableInjectionID) {
		t.Fatalf("expected VARIABLE_INJECTION finding, got: %+v", findings)
	}
	// Should be HIGH severity due to sink (make)
	var found *Finding
	for i, f := range findings {
		if f.ID == VariableInjectionID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("VARIABLE_INJECTION finding not found")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for sink usage, got: %v", found.Severity)
	}
}

func TestVariableInjection_SafeVariable_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{"echo $CI_COMMIT_SHA", "echo $CI_PROJECT_ID"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, VariableInjectionID) {
		t.Fatalf("did not expect VARIABLE_INJECTION finding for safe variables, got: %+v", findings)
	}
}

func TestVariableInjection_MRDescriptionInBash(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "process",
			Script: []string{"bash -c \"echo $CI_MERGE_REQUEST_DESCRIPTION\""},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, VariableInjectionID) {
		t.Fatalf("expected VARIABLE_INJECTION finding, got: %+v", findings)
	}
	// Should be HIGH: MR-triggered + sink (bash)
	var found *Finding
	for i, f := range findings {
		if f.ID == VariableInjectionID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("VARIABLE_INJECTION finding not found")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for MR+sink, got: %v", found.Severity)
	}
}

func TestVariableInjection_BraceFormat(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"npm run test -- ${CI_COMMIT_TITLE}"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, VariableInjectionID) {
		t.Fatalf("expected VARIABLE_INJECTION finding for ${VAR} format, got: %+v", findings)
	}
}

func TestExtractCIVariables(t *testing.T) {
	tests := []struct {
		line     string
		expected []string
	}{
		{"echo $CI_COMMIT_SHA", []string{"$CI_COMMIT_SHA"}},
		{"echo ${CI_PROJECT_ID}", []string{"$CI_PROJECT_ID"}},
		{"make TITLE=$CI_MERGE_REQUEST_TITLE MSG=$CI_COMMIT_MESSAGE", []string{"$CI_MERGE_REQUEST_TITLE", "$CI_COMMIT_MESSAGE"}},
		{"no variables here", []string{}},
		{"$CI_JOB_ID and ${CI_PIPELINE_ID}", []string{"$CI_JOB_ID", "$CI_PIPELINE_ID"}},
	}
	for _, tt := range tests {
		got := extractCIVariables(tt.line)
		if len(got) != len(tt.expected) {
			t.Errorf("extractCIVariables(%q) = %v, want %v", tt.line, got, tt.expected)
			continue
		}
		for i, v := range got {
			if v != tt.expected[i] {
				t.Errorf("extractCIVariables(%q)[%d] = %q, want %q", tt.line, i, v, tt.expected[i])
			}
		}
	}
}

func TestIsUnsafeVariable(t *testing.T) {
	tests := []struct {
		variable string
		unsafe   bool
	}{
		{"$CI_MERGE_REQUEST_TITLE", true},
		{"$CI_COMMIT_MESSAGE", true},
		{"$CI_COMMIT_SHA", false},
		{"$CI_PROJECT_ID", false},
		{"$CI_MERGE_REQUEST_DESCRIPTION", true},
		{"$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME", true},
		{"$CI_JOB_NAME", false},
	}
	for _, tt := range tests {
		got := isUnsafeVariable(tt.variable)
		if got != tt.unsafe {
			t.Errorf("isUnsafeVariable(%q) = %v, want %v", tt.variable, got, tt.unsafe)
		}
	}
}

func TestContainsSink(t *testing.T) {
	tests := []struct {
		line string
		sink bool
	}{
		{"make build", true},
		{"npm run test", true},
		{"pip install -r requirements.txt", true},
		{"bash -c 'echo hi'", true},
		{"./script.sh", true},
		{"echo hello", false},
		{"ls -la", false},
		{"go build ./...", false}, // "build" alone is not a sink, but "go build" is not in sink list
	}
	for _, tt := range tests {
		got := containsSink(tt.line)
		if got != tt.sink {
			t.Errorf("containsSink(%q) = %v, want %v", tt.line, got, tt.sink)
		}
	}
}

func TestForkMRRisks_UnprotectedMRJob(t *testing.T) {
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
	if !hasFindingID(findings, ForkMrUnprotectedID) {
		t.Fatalf("expected FORK_MR_UNPROTECTED finding, got: %+v", findings)
	}
}

func TestForkMRRisks_UnprotectedWithTags_HighSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{"deploy.sh"},
			Tags:   []string{"self-hosted"},
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
		if f.ID == ForkMrUnprotectedID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected FORK_MR_UNPROTECTED finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for self-hosted runner, got: %v", found.Severity)
	}
}

func TestForkMRRisks_ProtectedMRJob_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"echo test"},
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
	if hasFindingID(findings, ForkMrUnprotectedID) {
		t.Fatalf("did not expect FORK_MR_UNPROTECTED for protected job, got: %+v", findings)
	}
}

func TestArtifactPoisoning_ConsumingMRTriggeredArtifacts(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{
				Name:      "build",
				Script:    []string{"make build"},
				Artifacts: map[string]any{"paths": []any{"dist/"}},
				Rules: []any{
					map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
				},
			},
			{
				Name:   "deploy",
				Script: []string{"deploy.sh"},
				Needs:  []string{"build"},
			},
		},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ArtifactPoisoningID) {
		t.Fatalf("expected ARTIFACT_POISONING_RISK finding, got: %+v", findings)
	}
}

func TestArtifactPoisoning_DownstreamWithTags_HighSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{
				Name:      "build",
				Script:    []string{"make"},
				Artifacts: map[string]any{"paths": []any{"out/"}},
				Rules: []any{
					map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
				},
			},
			{
				Name:   "deploy",
				Script: []string{"./deploy"},
				Tags:   []string{"production"},
				Needs:  []string{"build"},
			},
		},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var found *Finding
	for i, f := range findings {
		if f.ID == ArtifactPoisoningID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected ARTIFACT_POISONING_RISK finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for downstream with tags, got: %v", found.Severity)
	}
}

func TestArtifactPoisoning_SafePipeline_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{
				Name:      "build",
				Script:    []string{"make"},
				Artifacts: map[string]any{"paths": []any{"out/"}},
			},
			{
				Name:   "test",
				Script: []string{"make test"},
				Needs:  []string{"build"},
			},
		},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, ArtifactPoisoningID) {
		t.Fatalf("did not expect ARTIFACT_POISONING_RISK for non-MR pipeline, got: %+v", findings)
	}
}

// --- FORK_SCRIPT_EXECUTION tests ---

const ForkScriptExecutionID = "FORK_SCRIPT_EXECUTION"

func TestForkScriptExecution_MakeInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"make build"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ForkScriptExecutionID) {
		t.Fatalf("expected FORK_SCRIPT_EXECUTION finding, got: %+v", findings)
	}
}

func TestForkScriptExecution_LocalScript(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"./scripts/test.sh"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ForkScriptExecutionID) {
		t.Fatalf("expected FORK_SCRIPT_EXECUTION finding, got: %+v", findings)
	}
}

func TestForkScriptExecution_ProtectedJob_NoFinding(t *testing.T) {
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
	if hasFindingID(findings, ForkScriptExecutionID) {
		t.Fatalf("did not expect FORK_SCRIPT_EXECUTION for protected job, got: %+v", findings)
	}
}

func TestForkScriptExecution_NonMRJob_NoFinding(t *testing.T) {
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
	if hasFindingID(findings, ForkScriptExecutionID) {
		t.Fatalf("did not expect FORK_SCRIPT_EXECUTION for non-MR job, got: %+v", findings)
	}
}

func TestForkScriptExecution_WithTags_HighSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"make deploy"},
			Tags:   []string{"self-hosted"},
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
		if f.ID == ForkScriptExecutionID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected FORK_SCRIPT_EXECUTION finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for self-hosted runner, got: %v", found.Severity)
	}
}

func TestForkScriptExecution_BashRelativePath(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "lint",
			Script: []string{"bash ci/lint.sh"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ForkScriptExecutionID) {
		t.Fatalf("expected FORK_SCRIPT_EXECUTION finding for 'bash ci/lint.sh', got: %+v", findings)
	}
}

func TestForkScriptExecution_GradleWrapper(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"./gradlew assemble"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, ForkScriptExecutionID) {
		t.Fatalf("expected FORK_SCRIPT_EXECUTION finding for ./gradlew, got: %+v", findings)
	}
}

func TestIsLocalScriptExecution(t *testing.T) {
	tests := []struct {
		line   string
		expect bool
	}{
		{"make build", true},
		{"./script.sh", true},
		{"./gradlew assemble", true},
		{".\\build.ps1", true},
		{"bash ci/lint.sh", true},
		{"sh scripts/deploy.sh", true},
		{"source .envrc", true},
		{"scripts/run.sh", true},
		{"echo hello", false},
		{"go build ./...", false},
		{"ls -la", false},
		{"apt-get install -y curl", false},
	}
	for _, tt := range tests {
		got := isLocalScriptExecution(tt.line)
		if got != tt.expect {
			t.Errorf("isLocalScriptExecution(%q) = %v, want %v", tt.line, got, tt.expect)
		}
	}
}

// --- AI_PROMPT_INJECTION tests ---

const AIPromptInjectionID = "AI_PROMPT_INJECTION"

func TestAIPromptInjection_ClaudeInMRJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "review",
			Script: []string{"claude review --pr"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, AIPromptInjectionID) {
		t.Fatalf("expected AI_PROMPT_INJECTION finding, got: %+v", findings)
	}
}

func TestAIPromptInjection_OpenAICurl(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "ai-review",
			Script: []string{"curl -X POST https://api.openai.com/v1/chat/completions -d @prompt.json"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, AIPromptInjectionID) {
		t.Fatalf("expected AI_PROMPT_INJECTION finding, got: %+v", findings)
	}
}

func TestAIPromptInjection_NonMRJob_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "review",
			Script: []string{"claude review --pr"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, AIPromptInjectionID) {
		t.Fatalf("did not expect AI_PROMPT_INJECTION for non-MR job, got: %+v", findings)
	}
}

func TestAIPromptInjection_WithGitPush_HighSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "ai-fix",
			Script: []string{"claude code --fix", "git commit -am 'AI fix'", "git push origin HEAD"},
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
		if f.ID == AIPromptInjectionID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected AI_PROMPT_INJECTION finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for AI+git push, got: %v", found.Severity)
	}
}

func TestAIPromptInjection_NoAI_NoFinding(t *testing.T) {
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
	if hasFindingID(findings, AIPromptInjectionID) {
		t.Fatalf("did not expect AI_PROMPT_INJECTION for job without AI tools, got: %+v", findings)
	}
}

func TestAIPromptInjection_CopilotWithUnsafeVar(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "copilot-review",
			Script: []string{"copilot review --context \"$CI_MERGE_REQUEST_DESCRIPTION\""},
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
		if f.ID == AIPromptInjectionID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected AI_PROMPT_INJECTION finding")
	}
	if found.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity for copilot + unsafe var, got: %v", found.Severity)
	}
}

func TestIsAIToolInvocation(t *testing.T) {
	tests := []struct {
		line   string
		expect bool
	}{
		{"claude review --pr", true},
		{"copilot review", true},
		{"curl https://api.openai.com/v1/chat", true},
		{"curl https://api.anthropic.com/v1/messages", true},
		{"pip install langchain", true},
		{"aider --model gpt-4", true},
		{"go test ./...", false},
		{"echo hello", false},
		{"make build", false},
	}
	for _, tt := range tests {
		got := isAIToolInvocation(tt.line)
		if got != tt.expect {
			t.Errorf("isAIToolInvocation(%q) = %v, want %v", tt.line, got, tt.expect)
		}
	}
}

func TestWithRecommendations_SpecificIDs(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantSub string
	}{
		{"variable injection", "VARIABLE_INJECTION", "attacker-controllable CI variables"},
		{"artifact poisoning", "ARTIFACT_POISONING_RISK", "artifact-producing MR pipelines"},
		{"workflow broad rules", "WORKFLOW_BROAD_RULES", "workflow rules"},
		{"fork script execution", "FORK_SCRIPT_EXECUTION", "repo-local scripts"},
		{"ai prompt injection", "AI_PROMPT_INJECTION", "AI code review"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []Finding{{ID: tt.id, Severity: SeverityMedium, Title: "test"}}
			out := withRecommendations(in)
			if out[0].Recommendation == "" {
				t.Fatalf("expected non-empty recommendation for %s", tt.id)
			}
			if out[0].Recommendation == "Review and harden configuration; apply least privilege and restrict triggers/inputs." {
				t.Fatalf("got default recommendation for %s, expected specific", tt.id)
			}
			if !strings.Contains(out[0].Recommendation, tt.wantSub) {
				t.Fatalf("recommendation for %s missing expected substring %q, got: %s", tt.id, tt.wantSub, out[0].Recommendation)
			}
		})
	}
}
