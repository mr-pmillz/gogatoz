package analyze

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Finding ID constants for pipeline governance checks.
const (
	IncludeForbiddenVersionID = "INCLUDE_FORBIDDEN_VERSION"
	IncludeMutableRefID       = "INCLUDE_MUTABLE_REF"
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
//   - INCLUDE_MUTABLE_REF: project/component includes pinned to any non-commit ref
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
	findings = append(findings, detectIncludeMutableRef(doc)...)
	findings = append(findings, detectSecurityJobWeakenedWith(doc, patterns)...)
	findings = append(findings, detectJobHardcoded(doc)...)

	return findings
}

// detectIncludeMutableRef identifies version tags, custom branches, shortened
// SHAs, and dynamic refs. Recent tag-poisoning incidents demonstrate that a
// release tag is not an immutable pin; only a known full commit SHA prevents a
// tag or branch from being moved to attacker-controlled code.
func detectIncludeMutableRef(doc *pipeline.Document) []Finding {
	if doc == nil {
		return nil
	}
	findings := make([]Finding, 0)
	for _, include := range doc.Includes {
		var evidence string
		switch include.Type {
		case pipeline.IncludeProject:
			ref := strings.TrimSpace(include.Ref)
			if ref == "" || isFullCommitSHA(ref) || isForbiddenBranchRef(ref) {
				continue
			}
			evidence = fmt.Sprintf("kind=project project=%s ref=%s files=%v", include.Project, ref, include.File)
		case pipeline.IncludeComponent:
			ref := componentIncludeRef(include.Component)
			if isFullCommitSHA(ref) {
				continue
			}
			evidence = fmt.Sprintf("kind=component component=%s ref=%s", include.Component, ref)
		default:
			continue
		}

		findings = append(findings, Finding{
			ID:       IncludeMutableRefID,
			Severity: SeverityHigh,
			Title:    "Include uses mutable release ref",
			Description: "The include is selected by a tag, branch, shortened SHA, or dynamic ref. " +
				"These refs can be moved to a different commit after review, allowing trusted CI code to be replaced without changing this pipeline.",
			Evidence: evidence,
			Recommendation: "Resolve the reviewed version to a known full commit SHA and pin the include to that SHA. " +
				"Monitor upstream advisories and update the pin only through reviewed changes.",
		})
	}
	return findings
}

func componentIncludeRef(component string) string {
	component = strings.TrimSpace(component)
	separator := strings.LastIndex(component, "@")
	if separator < 0 || separator == len(component)-1 {
		return ""
	}
	return strings.TrimSpace(component[separator+1:])
}

func isFullCommitSHA(ref string) bool {
	ref = strings.TrimSpace(ref)
	if len(ref) != 40 && len(ref) != 64 {
		return false
	}
	for _, character := range ref {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

// detectIncludeForbiddenVersion flags project includes that use a common branch
// name as the ref instead of a full commit SHA. Branch refs are mutable and
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
			Severity: SeverityHigh,
			Title:    "Include uses mutable branch ref",
			Description: "Project include is pinned to a branch name instead of a full commit SHA. " +
				"Branch refs are mutable — the upstream project can change the included code at any time without your pipeline's knowledge.",
			Evidence:       fmt.Sprintf("project=%s ref=%s files=%v", inc.Project, ref, inc.File),
			Recommendation: "Resolve the reviewed branch revision to a known full commit SHA and pin the include to that SHA.",
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
// (case-insensitive). Tags and commit SHAs will not match.
func isForbiddenBranchRef(ref string) bool {
	lower := strings.ToLower(ref)
	return slices.Contains(forbiddenBranchRefs, lower)
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
