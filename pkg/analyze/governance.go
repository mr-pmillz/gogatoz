package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Finding ID constants for pipeline governance checks.
const (
	IncludeForbiddenVersionID = "INCLUDE_FORBIDDEN_VERSION"
	SecurityJobWeakenedID     = "SECURITY_JOB_WEAKENED"
	JobHardcodedID            = "JOB_HARDCODED"
)

// forbiddenBranchRefs are branch names that indicate a mutable ref rather than
// a pinned tag or commit SHA. Checked case-insensitively.
var forbiddenBranchRefs = []string{
	"main",
	"master",
	"develop",
	"dev",
	"staging",
	"production",
	"release",
}

// securityJobPatterns are lowercase glob-style substrings that identify
// security-related CI jobs.
var securityJobPatterns = []string{
	"sast",
	"secret",
	"dast",
	"container_scanning",
	"dependency_scanning",
	"license_scanning",
	"code_quality",
	"security",
}

// detectGovernance checks for pipeline governance issues:
//   - INCLUDE_FORBIDDEN_VERSION: project includes pinned to a mutable branch ref
//   - SECURITY_JOB_WEAKENED: security jobs weakened by allow_failure, when:manual, or when:never rules
//   - JOB_HARDCODED: (stub) jobs defined inline instead of from includes/components
//
// When controls is non-nil and SecurityJobPatterns is non-empty, those patterns
// replace the default securityJobPatterns list for SECURITY_JOB_WEAKENED detection.
func detectGovernance(doc *pipeline.Document, controls *config.ControlsConfig) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	patterns := securityJobPatterns
	if controls != nil && len(controls.SecurityJobPatterns) > 0 {
		patterns = controls.SecurityJobPatterns
	}

	findings = append(findings, detectIncludeForbiddenVersion(doc)...)
	findings = append(findings, detectSecurityJobWeakenedWith(doc, patterns)...)
	findings = append(findings, detectJobHardcoded(doc)...)

	return findings
}

// detectIncludeForbiddenVersion flags project includes that use a common branch
// name as the ref instead of a tag or commit SHA. Branch refs are mutable and
// allow the upstream project to change included code without notice.
func detectIncludeForbiddenVersion(doc *pipeline.Document) []Finding {
	var findings []Finding
	for _, inc := range doc.Includes {
		if inc.Type != pipeline.IncludeProject {
			continue
		}
		ref := strings.TrimSpace(inc.Ref)
		if ref == "" {
			// Empty ref is already caught by INCLUDE_PROJECT_UNPINNED.
			continue
		}
		if !isForbiddenBranchRef(ref) {
			continue
		}
		findings = append(findings, Finding{
			ID:       IncludeForbiddenVersionID,
			Severity: SeverityMedium,
			Title:    "Include uses mutable branch ref instead of tag",
			Description: "Project include is pinned to a branch name instead of a tag or commit SHA. " +
				"Branch refs are mutable — the upstream project can change the included code at any time without your pipeline's knowledge.",
			Evidence: fmt.Sprintf("project=%s ref=%s files=%v", inc.Project, ref, inc.File),
		})
	}
	return findings
}

// detectSecurityJobWeakened flags security jobs that have been weakened through
// allow_failure:true, when:manual, or rules containing when:never.
// Uses the default securityJobPatterns list.
func detectSecurityJobWeakened(doc *pipeline.Document) []Finding {
	return detectSecurityJobWeakenedWith(doc, securityJobPatterns)
}

// detectSecurityJobWeakenedWith flags security jobs using a configurable patterns list.
func detectSecurityJobWeakenedWith(doc *pipeline.Document, patterns []string) []Finding {
	var findings []Finding
	for _, job := range doc.Jobs {
		if !isSecurityJobIn(job.Name, patterns) {
			continue
		}

		var reasons []string
		if job.AllowFailure {
			reasons = append(reasons, "allow_failure=true")
		}
		if strings.EqualFold(job.When, "manual") {
			reasons = append(reasons, "when=manual")
		}
		if rulesContainWhenNever(job.Rules) {
			reasons = append(reasons, "rules contain when:never")
		}

		if len(reasons) == 0 {
			continue
		}

		findings = append(findings, Finding{
			ID:       SecurityJobWeakenedID,
			Severity: SeverityCritical,
			Title:    "Security job weakened",
			Description: "A security job has been weakened by setting allow_failure, when: manual, or rules with when: never. " +
				"This can cause critical security scans to be skipped or ignored.",
			Evidence: fmt.Sprintf("job=%s weakened_by=%s", job.Name, strings.Join(reasons, ", ")),
			JobName:  job.Name,
		})
	}
	return findings
}

// detectJobHardcoded is a stub for detecting jobs defined inline instead of
// sourced from includes/components/templates. This detection requires provenance
// tracking (Document.Provenance) to be accurate — without it, heuristics
// produce too many false positives. Returns nil until provenance data is
// reliably available.
func detectJobHardcoded(_ *pipeline.Document) []Finding {
	return nil
}

// isSecurityJob returns true if the job name matches any of the known security
// job patterns. Matching is case-insensitive and uses substring containment
// (equivalent to *pattern* glob). Uses the default securityJobPatterns list.
func isSecurityJob(name string) bool {
	return isSecurityJobIn(name, securityJobPatterns)
}

// isSecurityJobIn returns true if the job name matches any pattern in the
// provided list. Matching is case-insensitive substring containment.
func isSecurityJobIn(name string, patterns []string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range patterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// isForbiddenBranchRef returns true if ref matches a common branch name
// (case-insensitive). Tags like "v1.2.3" and commit SHAs will not match.
func isForbiddenBranchRef(ref string) bool {
	lower := strings.ToLower(ref)
	for _, branch := range forbiddenBranchRefs {
		if lower == branch {
			return true
		}
	}
	return false
}

// rulesContainWhenNever checks whether the job's rules contain a "when: never"
// directive by serializing to JSON and searching for the pattern.
func rulesContainWhenNever(rules any) bool {
	if rules == nil {
		return false
	}
	text := toJSONString(rules)
	return strings.Contains(text, `"when":"never"`) || strings.Contains(text, `"when": "never"`)
}
