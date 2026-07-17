package analyze

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const RulesSecurityBypassID = "RULES_SECURITY_BYPASS"

var securityJobNames = []string{
	"sast", "dast", "secret_detection", "secret-detection",
	"container_scanning", "container-scanning",
	"license_scanning", "license-scanning", "license_management",
	"dependency_scanning", "dependency-scanning",
	"code_quality", "code-quality",
}

func detectRulesSecurityBypass(doc *pipeline.Document) []Finding {
	var findings []Finding

	for _, job := range doc.Jobs {
		if !isSecurityJobName(job.Name) {
			continue
		}
		if !hasRestrictiveRules(job, doc) {
			continue
		}

		findings = append(findings, Finding{
			ID:       RulesSecurityBypassID,
			Severity: SeverityHigh,
			Title:    "Security job with overly restrictive rules",
			Description: "Security job '" + job.Name + "' has rules:changes or rules:exists " +
				"patterns that are unlikely to match, effectively disabling the security scan. " +
				"This may indicate defense evasion.",
			Evidence: stringutil.TruncateEvidence("Job: "+job.Name, 200),
			JobName:  job.Name,
		})
	}

	return findings
}

func isSecurityJobName(name string) bool {
	lower := strings.ToLower(name)
	for _, secName := range securityJobNames {
		if lower == secName || strings.HasPrefix(lower, secName+"-") || strings.HasSuffix(lower, "-"+secName) {
			return true
		}
	}
	return false
}

func hasRestrictiveRules(job pipeline.Job, doc *pipeline.Document) bool {
	rawJob, ok := doc.Raw[job.Name].(map[string]any)
	if !ok {
		return false
	}
	rules, ok := rawJob["rules"].([]any)
	if !ok {
		return false
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		if hasNonexistentChanges(ruleMap) || hasNonexistentExists(ruleMap) {
			return true
		}
	}
	return false
}

func hasNonexistentChanges(rule map[string]any) bool {
	changes, ok := rule["changes"]
	if !ok {
		return false
	}
	switch v := changes.(type) {
	case []any:
		for _, c := range v {
			if s, ok := c.(string); ok && strings.Contains(s, "nonexistent") {
				return true
			}
		}
	case map[string]any:
		if paths, ok := v["paths"].([]any); ok {
			for _, p := range paths {
				if s, ok := p.(string); ok && strings.Contains(s, "nonexistent") {
					return true
				}
			}
		}
	}
	return false
}

func hasNonexistentExists(rule map[string]any) bool {
	exists, ok := rule["exists"]
	if !ok {
		return false
	}
	switch v := exists.(type) {
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && strings.Contains(s, "nonexistent") {
				return true
			}
		}
	case string:
		return strings.Contains(v, "nonexistent")
	}
	return false
}
