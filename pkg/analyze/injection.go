package analyze

import (
	"regexp"
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

// GitLab CI variables that are attacker-controllable and unsafe for direct use in scripts
var unsafeVariables = []string{
	// Merge request content (fork MRs can control these)
	"$CI_MERGE_REQUEST_TITLE",
	"$CI_MERGE_REQUEST_DESCRIPTION",
	"$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"$CI_MERGE_REQUEST_SOURCE_PROJECT_PATH",
	"$CI_MERGE_REQUEST_SOURCE_PROJECT_URL",
	"$CI_MERGE_REQUEST_REF_PATH",
	"$CI_MERGE_REQUEST_LABELS",
	"$CI_OPEN_MERGE_REQUESTS", // can contain attacker branch names
	// Commit metadata (can be spoofed by attacker)
	"$CI_COMMIT_MESSAGE",
	"$CI_COMMIT_TITLE",
	"$CI_COMMIT_DESCRIPTION",
	"$CI_COMMIT_REF_NAME", // branch/tag name
	"$CI_COMMIT_AUTHOR",
	"$CI_COMMIT_TAG_MESSAGE",
	// External PR integration (GitHub/Bitbucket PRs via GitLab)
	"$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
	"$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA",
	"$CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME",
	// Issue events (if triggered by issues)
	// Note: GitLab doesn't expose issue title/body as CI vars directly,
	// but webhooks/API integrations may pass them
}

// Unsafe variable patterns (regex) - variables containing these substrings are risky
var unsafePatterns = []string{
	"merge_request.*title",
	"merge_request.*description",
	"merge_request.*source.*branch",
	"commit.*message",
	"commit.*title",
	"commit.*description",
	"commit.*author",
	"external.*pull.*request",
}

// Command sinks that execute code - if unsafe variables appear in these, it's HIGH severity
var sinks = []string{
	"make", "gradle", "gradlew", "mvn", "maven", "ant",
	"npm run", "npm install", "yarn", "pnpm run", "pnpm install", "bun",
	"pip install", "poetry", "tox", "pytest",
	"go run", "go generate",
	"cargo", "bundle", "rake", "rubocop",
	"terraform", "tflint",
	"eslint", "prettier", "stylelint", "webpack",
	"mkdocs", "goreleaser", "sonar-scanner",
	"dotnet build", "msbuild",
	"rails", "pre-commit",
	"bash", "sh", "zsh", "pwsh", "powershell",
	"eval", "exec",
}

var (
	// Regex to find GitLab CI variable references: $VAR or ${VAR}
	ciVarRegex = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)\}?`)
	// Regex for unsafe patterns (case-insensitive)
	unsafePatternRegexes []*regexp.Regexp
)

func init() {
	for _, pat := range unsafePatterns {
		unsafePatternRegexes = append(unsafePatternRegexes, regexp.MustCompile(`(?i)`+pat))
	}
}

// detectVariableInjection scans job scripts for unsafe CI variable usage
func detectVariableInjection(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		// Check if job is triggered by MR or external events
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)

		for _, scriptLine := range effectiveScripts(job, doc) {
			// Extract CI variables from script line
			vars := extractCIVariables(scriptLine)
			if len(vars) == 0 {
				continue
			}

			// Check if any unsafe variables are used
			for _, v := range vars {
				if isUnsafeVariable(v) {
					severity := SeverityMedium
					desc := "Job script uses attacker-controllable CI variable without sanitization."

					// If MR-triggered and uses unsafe var, higher severity
					if mrTriggered {
						severity = SeverityHigh
						desc = "MR-triggered job uses attacker-controllable variable from fork MR without sanitization. This enables pipeline injection attacks."
					}

					// If variable is used in a command sink, it's HIGH severity
					if containsSink(scriptLine) {
						severity = SeverityHigh
						desc += " Variable is used in a command that executes code (injection sink)."
					}

					findings = append(findings, Finding{
						ID:          "VARIABLE_INJECTION",
						Severity:    severity,
						Title:       "Unsafe CI variable usage in script",
						Description: desc,
						Evidence:    stringutil.TruncateEvidence("variable="+v+" in: "+scriptLine, 200),
						JobName:     job.Name,
					})
				}
			}
		}
	}

	return findings
}

// extractCIVariables finds all $VAR or ${VAR} references in a script line
func extractCIVariables(line string) []string {
	matches := ciVarRegex.FindAllStringSubmatch(line, -1)
	var vars []string
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) > 1 {
			v := "$" + m[1]
			if !seen[v] {
				vars = append(vars, v)
				seen[v] = true
			}
		}
	}
	return vars
}

// isUnsafeVariable checks if a variable is in the unsafe list or matches unsafe patterns
func isUnsafeVariable(v string) bool {
	// Exact match
	for _, unsafe := range unsafeVariables {
		if strings.EqualFold(v, unsafe) {
			return true
		}
	}
	// Pattern match
	vLower := strings.ToLower(v)
	for _, re := range unsafePatternRegexes {
		if re.MatchString(vLower) {
			return true
		}
	}
	return false
}

// containsSink checks if a script line contains a command sink
func containsSink(line string) bool {
	lineLower := strings.ToLower(line)
	for _, sink := range sinks {
		if strings.Contains(lineLower, sink) {
			return true
		}
	}
	// Check for local script execution patterns: ./ or .\\ but not ./... (Go wildcard)
	// Pattern: ./ followed by something that's not just dots (to avoid ./... false positive)
	if strings.Contains(line, "./") && !strings.Contains(line, "./.") {
		return true
	}
	if strings.Contains(line, ".\\") {
		return true
	}
	return false
}

// detectForkMRRisks identifies jobs that run on fork MRs without adequate protection
func detectForkMRRisks(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		// Check if job triggers on MR events
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mrTriggered {
			continue
		}

		// Check if there's any fork protection in rules
		hasForkProtection := checkForkProtection(job.Rules)

		// If MR-triggered without fork protection, it's risky
		if !hasForkProtection {
			severity := SeverityMedium
			desc := "Job runs on merge request events without explicit fork protection. Fork MRs can trigger this job and potentially access secrets or modify artifacts."

			// Higher severity if job has tags (self-hosted runners) or uses artifacts
			if len(job.Tags) > 0 {
				severity = SeverityHigh
				desc += " Job targets self-hosted runners, enabling potential runner takeover from fork MRs."
			} else if job.Artifacts != nil {
				severity = SeverityHigh
				desc += " Job produces artifacts that could be poisoned by fork MR authors."
			}

			findings = append(findings, Finding{
				ID:          "FORK_MR_UNPROTECTED",
				Severity:    severity,
				Title:       "MR job lacks fork protection",
				Description: desc,
				Evidence:    stringutil.TruncateEvidence("rules="+toJSONString(job.Rules), 200),
				JobName:     job.Name,
			})
		}
	}

	return findings
}

// checkForkProtection returns true if rules include protection against fork MRs
func checkForkProtection(rules any) bool {
	if rules == nil {
		return false
	}
	rulesStr := strings.ToLower(toJSONString(rules))
	// Look for patterns that indicate fork protection:
	// - Checking if source project equals target project
	// - Protected branch checks
	// - Approval requirements
	protectionPatterns := []string{
		"ci_merge_request_source_project_path == $ci_merge_request_target_project_path",
		"ci_merge_request_source_project_id == $ci_merge_request_target_project_id",
		"protected",
		"approval",
	}
	for _, pat := range protectionPatterns {
		if strings.Contains(rulesStr, pat) {
			return true
		}
	}
	return false
}

// Local script execution patterns for fork MR risk detection
var localScriptPatterns = []string{
	"./gradlew", "./mvnw", "./vendor/bin/",
	"scripts/", "script/", "hack/",
}

// isLocalScriptExecution returns true if a script line executes a repo-local file
// that a fork MR author could modify.
func isLocalScriptExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	// ./ prefix (but not ./... which is a Go wildcard)
	if strings.HasPrefix(trimmed, "./") && trimmed != "./..." && !strings.HasPrefix(trimmed, "./... ") {
		return true
	}
	// .\ prefix (Windows)
	if strings.HasPrefix(trimmed, ".\\") {
		return true
	}

	lower := strings.ToLower(trimmed)

	// Known local script patterns
	for _, pat := range localScriptPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}

	// "make" as first command token (Makefile is repo-local and modifiable)
	tokens := strings.Fields(lower)
	if len(tokens) > 0 && tokens[0] == "make" {
		return true
	}

	// "bash <path>" or "sh <path>" with relative path
	if len(tokens) >= 2 && (tokens[0] == "bash" || tokens[0] == "sh" || tokens[0] == "zsh") {
		arg := tokens[1]
		// Relative path: doesn't start with / or $ or -
		if !strings.HasPrefix(arg, "/") && !strings.HasPrefix(arg, "$") && !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "<") {
			return true
		}
	}

	// "source <relative-path>"
	if len(tokens) >= 2 && tokens[0] == "source" {
		arg := tokens[1]
		if !strings.HasPrefix(arg, "/") && !strings.HasPrefix(arg, "$") {
			return true
		}
	}

	return false
}

// detectForkScriptExecution flags MR-triggered jobs that execute repo-local scripts
// without fork protection. Fork MR authors can modify these scripts to inject code.
func detectForkScriptExecution(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mrTriggered {
			continue
		}
		if checkForkProtection(job.Rules) {
			continue
		}

		// Check each script line for local script execution (before, script, after)
		for _, line := range effectiveScripts(job, doc) {
			if isLocalScriptExecution(line) {
				severity := SeverityMedium
				desc := "MR-triggered job executes a repo-local script without fork protection. Fork MR authors can modify this script to inject arbitrary code."
				if len(job.Tags) > 0 {
					severity = SeverityHigh
					desc += " Job targets self-hosted runners, amplifying the impact."
				}
				findings = append(findings, Finding{
					ID:          "FORK_SCRIPT_EXECUTION",
					Severity:    severity,
					Title:       "Fork MR can modify executed repo script",
					Description: desc,
					Evidence:    stringutil.TruncateEvidence("script="+line, 200),
					JobName:     job.Name,
				})
				break // one finding per job is sufficient
			}
		}
	}
	return findings
}

// AI tool patterns for prompt injection detection
var aiToolPatterns = []string{
	// CLI tools
	"claude", "copilot", "aider", "cursor", "cody", "codex",
	// API endpoints
	"api.anthropic.com", "api.openai.com",
	// SDK/package names
	"anthropic", "openai", "langchain", "llama-index", "llamaindex",
	"@anthropic-ai/sdk",
	// GitHub Actions-style references
	"actions/ai-", "github/copilot-", "anthropics/",
}

// isAIToolInvocation returns true if a script line invokes an AI tool or API.
func isAIToolInvocation(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	for _, pat := range aiToolPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// jobHasWriteCapability returns true if script lines suggest the job can push commits.
func jobHasWriteCapability(scriptLines []string) bool {
	for _, line := range scriptLines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "git push") || strings.Contains(lower, "git commit") {
			return true
		}
	}
	return false
}

// detectAIPromptInjection flags MR-triggered jobs that invoke AI tools,
// which can be exploited via poisoned config files (CLAUDE.md, .cursorrules, etc.)
// or attacker-controlled MR content passed as prompts.
func detectAIPromptInjection(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mrTriggered {
			continue
		}

		// Check if any script line invokes AI tools
		var aiLine string
		for _, line := range job.Script {
			if isAIToolInvocation(line) {
				aiLine = line
				break
			}
		}
		if aiLine == "" {
			continue
		}

		severity := SeverityMedium
		var desc strings.Builder
		desc.WriteString("MR-triggered job invokes an AI tool that may process untrusted content from fork MRs. Attackers can poison AI config files (CLAUDE.md, .cursorrules) or MR descriptions to manipulate the AI into malicious actions.")

		// Escalate if job can push commits (AI-driven code changes)
		if jobHasWriteCapability(job.Script) {
			severity = SeverityHigh
			desc.WriteString(" Job has git write capability, enabling AI-driven malicious commits.")
		}

		// Escalate if job uses unsafe variables alongside AI
		for _, line := range job.Script {
			vars := extractCIVariables(line)
			if slices.ContainsFunc(vars, isUnsafeVariable) {
				severity = SeverityHigh
				desc.WriteString(" Attacker-controllable CI variables are passed to the AI tool.")
			}
			if severity == SeverityHigh {
				break
			}
		}

		// Escalate if no fork protection
		if !checkForkProtection(job.Rules) && severity != SeverityHigh {
			severity = SeverityHigh
			desc.WriteString(" No fork protection detected.")
		}

		findings = append(findings, Finding{
			ID:          "AI_PROMPT_INJECTION",
			Severity:    severity,
			Title:       "AI tool in MR-triggered job vulnerable to prompt injection",
			Description: desc.String(),
			Evidence:    stringutil.TruncateEvidence("ai_invocation="+aiLine, 200),
			JobName:     job.Name,
		})
	}
	return findings
}

// detectArtifactPoisoning identifies jobs that consume artifacts from potentially untrusted sources
func detectArtifactPoisoning(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	// Build a map of jobs that produce artifacts and their triggers
	artifactProducers := map[string]bool{} // jobName -> isMRTriggered
	for _, job := range doc.Jobs {
		if job.Artifacts != nil {
			mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
			artifactProducers[job.Name] = mrTriggered
		}
	}

	// Check jobs that depend on other jobs (via needs)
	for _, job := range doc.Jobs {
		if len(job.Needs) == 0 {
			continue
		}

		// Check if any needed job is MR-triggered (potential artifact poisoning)
		var riskyNeeds []string
		for _, need := range job.Needs {
			if isMRTriggered, exists := artifactProducers[need]; exists && isMRTriggered {
				riskyNeeds = append(riskyNeeds, need)
			}
		}

		if len(riskyNeeds) > 0 {
			severity := SeverityMedium
			desc := "Job depends on artifacts from MR-triggered jobs. Fork MR authors can poison artifacts and compromise downstream jobs."

			// Higher severity if downstream job has privileges (tags, deployment, etc.)
			if len(job.Tags) > 0 {
				severity = SeverityHigh
				desc += " Downstream job runs on self-hosted runners, amplifying the attack surface."
			}

			findings = append(findings, Finding{
				ID:          "ARTIFACT_POISONING_RISK",
				Severity:    severity,
				Title:       "Job consumes artifacts from MR-triggered sources",
				Description: desc,
				Evidence:    stringutil.TruncateEvidence("needs="+strings.Join(riskyNeeds, ","), 150),
				JobName:     job.Name,
			})
		}
	}

	return findings
}
