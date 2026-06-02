package analyze

import "strings"

// FPRule defines a false positive detection rule for enumerate findings.
type FPRule struct {
	ID          string
	Description string
	Match       func(f Finding) bool
}

// DefaultFPRules returns the built-in false positive rules.
// Rules are evaluated in order; first match wins.
func DefaultFPRules() []FPRule {
	return []FPRule{
		gitlabCIFlagRule(),
		pagesArtifactsRule(),
	}
}

// ApplyFPRules returns a new slice of findings with FalsePositive and
// FalsePositiveReason populated for any matching rules. The input slice
// is not modified.
func ApplyFPRules(findings []Finding, rules []FPRule) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		for _, rule := range rules {
			if rule.Match(out[i]) {
				out[i].FalsePositive = true
				out[i].FalsePositiveReason = rule.ID
				break
			}
		}
	}
	return out
}

// FilterTruePositives returns only findings not marked as false positive.
func FilterTruePositives(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if !f.FalsePositive {
			out = append(out, f)
		}
	}
	return out
}

// gitlabCIFlagRule detects PLAINTEXT_SECRET findings where the evidence
// contains a GitLab CI feature flag variable name (e.g., SECRET_DETECTION_ENABLED).
// These are boolean configuration toggles, not actual secrets.
func gitlabCIFlagRule() FPRule {
	ciFlags := []string{
		"SECRET_DETECTION_ENABLED",
		"SECRET_DETECTION_HISTORIC_ENABLED",
		"SECRET_DETECTION_ENABLE_MR_PIPELINES",
		"SAST_DISABLED",
		"DS_EXCLUDED_ANALYZERS",
		"SAST_EXCLUDED_ANALYZERS",
		"CODE_QUALITY_DISABLED",
		"CONTAINER_SCANNING_DISABLED",
		"DEPENDENCY_SCANNING_DISABLED",
		"LICENSE_MANAGEMENT_SETUP_DISABLED",
	}
	return FPRule{
		ID:          "FP_GITLAB_CI_FLAG",
		Description: "GitLab CI feature flag variable, not an actual secret",
		Match: func(f Finding) bool {
			if f.ID != "PLAINTEXT_SECRET" && f.ID != "PLAINTEXT_SECRET_JOB" {
				return false
			}
			upper := strings.ToUpper(f.Evidence)
			for _, flag := range ciFlags {
				if strings.Contains(upper, flag) {
					return true
				}
			}
			return false
		},
	}
}

// pagesArtifactsRule detects ARTIFACTS_NO_EXPIRE findings on GitLab Pages
// jobs. Pages requires artifacts to serve content, so the no-expiry
// finding is expected and not actionable.
func pagesArtifactsRule() FPRule {
	return FPRule{
		ID:          "FP_PAGES_ARTIFACTS",
		Description: "GitLab Pages job requires artifacts, expected behavior",
		Match: func(f Finding) bool {
			if f.ID != "ARTIFACTS_NO_EXPIRE" {
				return false
			}
			return strings.EqualFold(f.JobName, "pages")
		},
	}
}
