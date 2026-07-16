package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

// Finding ID constants for supply chain attack techniques.
const (
	ScriptInjectionRiskID = "SCRIPT_INJECTION_RISK"
	SelfMergePossibleID   = "SELF_MERGE_POSSIBLE"
	CachePoisoningRiskID  = "CACHE_POISONING_RISK"
)

// Extended local script execution patterns including python and ruby interpreters.
var scriptInterpreters = []string{
	"bash", "sh", "zsh", "python", "python3", "ruby", "perl", "node",
}

// isExternalScriptExecution returns true if a script line references an external
// script from the repository (e.g., ./scripts/deploy.sh, bash scripts/test.sh,
// make deploy, source .envrc). This overlaps with isLocalScriptExecution but
// intentionally casts a wider net for the SCRIPT_INJECTION_RISK finding.
func isExternalScriptExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	// ./ prefix (but not ./... which is a Go wildcard)
	if strings.HasPrefix(trimmed, "./") && !strings.HasPrefix(trimmed, "./.") {
		return true
	}
	// .\ prefix (Windows)
	if strings.HasPrefix(trimmed, ".\\") {
		return true
	}

	lower := strings.ToLower(trimmed)
	tokens := strings.Fields(lower)
	if len(tokens) == 0 {
		return false
	}

	// "make" as first command token (Makefile is repo-local and modifiable)
	if tokens[0] == "make" {
		return true
	}

	// Interpreter + relative path: bash path, sh path, python path, etc.
	if len(tokens) >= 2 {
		for _, interp := range scriptInterpreters {
			if tokens[0] == interp {
				arg := tokens[1]
				// Relative path: doesn't start with / or $ or - or <
				if !strings.HasPrefix(arg, "/") && !strings.HasPrefix(arg, "$") && !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "<") {
					return true
				}
			}
		}
	}

	// "source <relative-path>"
	if len(tokens) >= 2 && (tokens[0] == "source" || tokens[0] == ".") {
		arg := tokens[1]
		if !strings.HasPrefix(arg, "/") && !strings.HasPrefix(arg, "$") {
			return true
		}
	}

	// Known local script directory patterns
	for _, pat := range localScriptPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}

	return false
}

// detectScriptInjectionRisk flags MR-triggered jobs that execute external scripts
// from the repository. An attacker can modify these scripts in an MR without changing
// the CI config itself, making the attack harder to detect in code review.
func detectScriptInjectionRisk(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mrTriggered {
			continue
		}

		// Check all script phases for external script execution
		for _, line := range effectiveScripts(job, doc) {
			if isExternalScriptExecution(line) {
				severity := SeverityHigh
				desc := "MR-triggered job executes an external script from the repository. An attacker can modify these scripts in an MR without changing the CI config, making the attack harder to detect during code review."

				// Downgrade if fork protection is present
				if checkForkProtection(job.Rules) {
					severity = SeverityMedium
					desc += " Fork protection rules are present but may be insufficient."
				}

				findings = append(findings, Finding{
					ID:          ScriptInjectionRiskID,
					Severity:    severity,
					Title:       "MR job executes external repo script",
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

// detectSelfMergePossible emits a heuristic finding when MR-triggered jobs lack
// branch protection indicators. Without required approvers or protected branch
// rules, an attacker may be able to self-approve and merge an MR, enabling supply
// chain attacks.
func detectSelfMergePossible(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	// Check if any MR-triggered job exists without branch protection hints
	hasMRJobs := false
	hasAnyProtection := false

	for _, job := range doc.Jobs {
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mrTriggered {
			continue
		}
		hasMRJobs = true

		// Check for approval/protection patterns in rules
		if checkBranchProtectionHints(job.Rules) {
			hasAnyProtection = true
			break
		}
	}

	// Also check workflow-level rules for protection hints
	if !hasAnyProtection && doc.Workflow.Rules != nil {
		if checkBranchProtectionHints(doc.Workflow.Rules) {
			hasAnyProtection = true
		}
	}

	if hasMRJobs && !hasAnyProtection {
		findings = append(findings, Finding{
			ID:          SelfMergePossibleID,
			Severity:    SeverityHigh,
			Title:       "No merge approval enforcement detected in CI config",
			Description: "Pipeline has MR-triggered jobs but no branch protection or approval enforcement detected in CI rules. If the project allows self-merge (0-1 required approvers), an attacker can create an MR, self-approve, and merge to execute supply chain attacks. Verify project settings require multiple approvals.",
			Evidence:    "No approval_required, protected branch, or CODEOWNERS rules detected in CI configuration",
		})
	}

	return findings
}

// checkBranchProtectionHints returns true if rules contain indicators of branch
// protection enforcement (approvals, protected refs, CODEOWNERS).
func checkBranchProtectionHints(rules any) bool {
	if rules == nil {
		return false
	}
	rulesStr := strings.ToLower(toJSONString(rules))
	protectionPatterns := []string{
		"approval",
		"protected",
		"codeowners",
		"ci_commit_ref_protected",
		"approvals_required",
		"merge_request_approved",
	}
	for _, pat := range protectionPatterns {
		if strings.Contains(rulesStr, pat) {
			return true
		}
	}
	return false
}

// detectCachePoisoningRisk flags MR-triggered jobs that use cache with push or
// pull-push policy. An attacker can poison the cache from an MR pipeline, which
// then affects subsequent builds on the default branch.
func detectCachePoisoningRisk(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mrTriggered {
			continue
		}

		if job.Cache == nil {
			continue
		}

		policy := extractCachePolicy(job.Cache)
		if policy == "" {
			// Default policy is pull-push, which is risky
			policy = "pull-push (default)"
		}

		isPushPolicy := strings.Contains(strings.ToLower(policy), "push")
		if !isPushPolicy {
			continue
		}

		severity := SeverityMedium
		desc := fmt.Sprintf(
			"MR-triggered job uses cache with policy %q. An attacker can poison the cache from a fork MR pipeline, injecting malicious content that affects subsequent builds on the default branch.",
			policy,
		)

		// Escalate if no fork protection
		if !checkForkProtection(job.Rules) {
			severity = SeverityHigh
			desc += " No fork protection detected."
		}

		findings = append(findings, Finding{
			ID:          CachePoisoningRiskID,
			Severity:    severity,
			Title:       "MR job can poison shared cache",
			Description: desc,
			Evidence:    stringutil.TruncateEvidence(fmt.Sprintf("cache=%s policy=%s", toJSONString(job.Cache), policy), 200),
			JobName:     job.Name,
		})
	}
	return findings
}

// extractCachePolicy extracts the cache policy from a cache configuration map.
// GitLab cache can be a map with "policy" key, or an array of cache configs.
func extractCachePolicy(cache map[string]any) string {
	// Direct policy key
	if p, ok := cache["policy"]; ok {
		if s, ok := p.(string); ok {
			return s
		}
	}
	return ""
}
