package enumerate

import (
	"encoding/json"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// ProtectionLevel classifies how strongly a job is gated to protected contexts.
type ProtectionLevel int

const (
	// ProtectionNone means no protection signal detected.
	ProtectionNone ProtectionLevel = iota
	// ProtectionHeuristic means rules JSON mentions "protected"/"approval" keywords.
	ProtectionHeuristic
	// ProtectionStructural means rules:if structurally gates on CI_COMMIT_REF_PROTECTED
	// or only: contains "protected".
	ProtectionStructural
	// ProtectionBranchGated means rules:if restricts to branches that are all protected
	// (verified against the project's protected branches list).
	ProtectionBranchGated
)

// isProtectionEligible delegates to isRunnerRelatedFinding (adjust.go).
func isProtectionEligible(id string) bool {
	return isRunnerRelatedFinding(id)
}

// adjustFindingsForProtectedBranches downgrades severity for runner-related findings
// when the corresponding job appears to be restricted to protected branches or
// otherwise gated, to reduce false positives.
//
// Downgrade behavior depends on the protection level:
//   - ProtectionStructural / ProtectionBranchGated → full downgrade (HIGH→MEDIUM, MEDIUM→LOW)
//   - ProtectionHeuristic → partial: only HIGH→MEDIUM (MEDIUM stays MEDIUM)
//
// An evidence annotation is appended to each adjusted finding.
func adjustFindingsForProtectedBranches(r *Result, doc *pipeline.Document) {
	if r == nil || doc == nil || len(r.Findings) == 0 || len(doc.Jobs) == 0 {
		return
	}
	// Build lookup: jobName → ProtectionLevel
	levels := make(map[string]ProtectionLevel, len(doc.Jobs))
	for _, j := range doc.Jobs {
		pl := classifyJobProtection(j, r.ProtectedBranches)
		if pl != ProtectionNone {
			levels[j.Name] = pl
		}
	}
	if len(levels) == 0 {
		return
	}
	for i := range r.Findings {
		fn := &r.Findings[i]
		if fn.JobName == "" {
			continue
		}
		pl, ok := levels[fn.JobName]
		if !ok || pl == ProtectionNone {
			continue
		}
		id := strings.ToUpper(fn.ID)
		if !isProtectionEligible(id) {
			continue
		}
		switch pl {
		case ProtectionStructural:
			fn.Severity = downgradeSeverity(fn.Severity)
			fn.Evidence += " [gated: CI_COMMIT_REF_PROTECTED]"
		case ProtectionBranchGated:
			fn.Severity = downgradeSeverity(fn.Severity)
			fn.Evidence += " [gated: branch-restricted to protected branches]"
		case ProtectionHeuristic:
			switch fn.Severity {
			case analyze.SeverityCritical:
				fn.Severity = analyze.SeverityHigh
			case analyze.SeverityHigh:
				fn.Severity = analyze.SeverityMedium
			}
			fn.Evidence += " [heuristic: rules mention protected/approval]"
		}
	}
}

func downgradeSeverity(s analyze.Severity) analyze.Severity {
	switch s {
	case analyze.SeverityCritical:
		return analyze.SeverityHigh
	case analyze.SeverityHigh:
		return analyze.SeverityMedium
	case analyze.SeverityMedium:
		return analyze.SeverityLow
	default:
		return s // LOW and INFORMATIONAL stay put
	}
}

// classifyJobProtection determines the protection level of a job by examining
// its rules and only blocks, optionally cross-referencing the project's
// protected branches list.
//
// Order of checks:
//  1. If the job has an always-run rule, skip structural/branch checks (fall to heuristic/none).
//  2. Structural: rules:if gates on CI_COMMIT_REF_PROTECTED == "true".
//  3. Structural: only: contains "protected" keyword.
//  4. Branch-gated: rules:if restricts to branches that are all protected.
//  5. Heuristic: rules JSON mentions "protected"/"approval"/"approved".
//  6. None.
func classifyJobProtection(j pipeline.Job, protectedBranches []string) ProtectionLevel {
	// An always-run rule (no "if", when=always/on_success/empty) means the job
	// runs unconditionally, so no protection classification applies.
	if jobHasAlwaysRule(j.Rules) {
		return ProtectionNone
	}

	// Structural check: rules:if gates on CI_COMMIT_REF_PROTECTED
	if rulesGateOnRefProtected(j.Rules) {
		return ProtectionStructural
	}

	// Structural check: only: protected
	if onlyContainsProtected(j.Only) {
		return ProtectionStructural
	}

	// Branch-gated check: rules restrict to branches that are all protected
	if len(protectedBranches) > 0 && rulesGateToBranches(j.Rules, protectedBranches) {
		return ProtectionBranchGated
	}

	// Heuristic fallback: JSON substring check
	if isJobProtectedHeuristic(j) {
		return ProtectionHeuristic
	}

	return ProtectionNone
}

// rulesGateOnRefProtected returns true if the rules array contains at least one
// rule whose "if" expression evaluates to true when CI_COMMIT_REF_PROTECTED is
// "true" and no non-"when:never" rule evaluates to true when it is "false".
func rulesGateOnRefProtected(rules any) bool {
	arr, ok := rules.([]any)
	if !ok || len(arr) == 0 {
		return false
	}

	protectedCtx := map[string]string{"CI_COMMIT_REF_PROTECTED": "true"}
	unprotectedCtx := map[string]string{"CI_COMMIT_REF_PROTECTED": "false"}

	matchesProtected := false
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifVal, _ := m["if"].(string)
		if strings.TrimSpace(ifVal) == "" {
			continue
		}
		whenVal, _ := m["when"].(string)
		isNever := strings.EqualFold(strings.TrimSpace(whenVal), "never")

		if analyze.EvaluateIf(ifVal, protectedCtx) && !isNever {
			matchesProtected = true
		}
		if analyze.EvaluateIf(ifVal, unprotectedCtx) && !isNever {
			// A non-never rule matches when unprotected — not structurally gated
			return false
		}
	}

	return matchesProtected
}

// onlyContainsProtected checks if the job's only: block contains the
// "protected" keyword (same logic as the old isJobProtected only: parsing).
func onlyContainsProtected(only any) bool {
	switch t := only.(type) {
	case []any:
		for _, it := range t {
			if s, ok := it.(string); ok && strings.EqualFold(strings.TrimSpace(s), "protected") {
				return true
			}
		}
	case map[string]any:
		if refs, ok := t["refs"]; ok {
			if arr, ok := refs.([]any); ok {
				for _, it := range arr {
					if s, ok := it.(string); ok && strings.EqualFold(strings.TrimSpace(s), "protected") {
						return true
					}
				}
			}
		}
	case string:
		if strings.EqualFold(strings.TrimSpace(t), "protected") {
			return true
		}
	}
	return false
}

// rulesGateToBranches returns true if every protected branch causes the job to
// run AND a synthetic non-protected branch does not cause it to run. This
// establishes that the job is restricted to the protected branch set.
func rulesGateToBranches(rules any, protectedBranches []string) bool {
	arr, ok := rules.([]any)
	if !ok || len(arr) == 0 || len(protectedBranches) == 0 {
		return false
	}

	// Check that the job runs for every protected branch
	for _, branch := range protectedBranches {
		ctx := map[string]string{
			"CI_COMMIT_BRANCH":   branch,
			"CI_COMMIT_REF_NAME": branch,
		}
		if !rulesMatchContext(arr, ctx) {
			return false
		}
	}

	// Check that a synthetic unprotected branch does NOT trigger the job
	fakeCtx := map[string]string{
		"CI_COMMIT_BRANCH":   "__gogatoz_test_unprotected__",
		"CI_COMMIT_REF_NAME": "__gogatoz_test_unprotected__",
	}
	return !rulesMatchContext(arr, fakeCtx)
}

// rulesMatchContext returns true if at least one rule in arr matches the given
// context and is not "when: never".
func rulesMatchContext(arr []any, ctx map[string]string) bool {
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifVal, _ := m["if"].(string)
		if strings.TrimSpace(ifVal) == "" {
			continue
		}
		whenVal, _ := m["when"].(string)
		if strings.EqualFold(strings.TrimSpace(whenVal), "never") {
			continue
		}
		if analyze.EvaluateIf(ifVal, ctx) {
			return true
		}
	}
	return false
}

// jobHasAlwaysRule returns true if the rules array contains an entry with no
// "if" clause and a "when" value that defaults to running (empty, "always", or
// "on_success"). Such a rule means the job will run unconditionally regardless
// of branch protection.
func jobHasAlwaysRule(rules any) bool {
	arr, ok := rules.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifVal, _ := m["if"].(string)
		if strings.TrimSpace(ifVal) != "" {
			// Has an "if" condition — not an unconditional always rule
			continue
		}
		whenVal, _ := m["when"].(string)
		w := strings.ToLower(strings.TrimSpace(whenVal))
		// Empty when defaults to "on_success", which is effectively always-run
		if w == "" || w == "always" || w == "on_success" {
			return true
		}
	}
	return false
}

// isJobProtectedHeuristic applies lightweight heuristics to detect protected/gated jobs.
// It checks for:
// - only: ["protected"] or only.refs containing "protected"
// - rules JSON containing the substring "protected" or approval keywords
func isJobProtectedHeuristic(j pipeline.Job) bool {
	// only:
	if onlyContainsProtected(j.Only) {
		return true
	}
	// rules:
	if j.Rules != nil {
		b, err := json.Marshal(j.Rules)
		if err != nil {
			return false
		}
		txt := strings.ToLower(string(b))
		if strings.Contains(txt, "protected") || strings.Contains(txt, "approval") || strings.Contains(txt, "approved") {
			return true
		}
	}
	return false
}
