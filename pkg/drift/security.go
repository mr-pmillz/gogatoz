package drift

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

// SecurityChange represents a security-relevant assessment of a config change.
type SecurityChange struct {
	Severity    analyze.Severity `json:"severity"`
	Category    string           `json:"category"`
	Description string           `json:"description"`
	Change      Change           `json:"change"`
}

var securityJobPatterns = []string{
	"sast", "dast", "secret", "dependency", "container_scan",
	"license_scan", "security", "vulnerability", "gemnasium",
	"trivy", "semgrep", "bandit", "gosec", "brakeman",
}

// AssessSecurityImpact evaluates a set of changes for security relevance.
func AssessSecurityImpact(changes []Change) []SecurityChange {
	var impacts []SecurityChange
	for _, c := range changes {
		if si, ok := assessChange(c); ok {
			impacts = append(impacts, si)
		}
	}
	return impacts
}

func assessChange(c Change) (SecurityChange, bool) {
	switch {
	case c.Type == ChangeRemoved && c.Category == CategoryJob && isSecurityJob(c.Name):
		return SecurityChange{
			Severity:    analyze.SeverityCritical,
			Category:    "security_job_removed",
			Description: fmt.Sprintf("Security scanning job '%s' was removed", c.Name),
			Change:      c,
		}, true
	case c.Type == ChangeAdded && c.Category == CategoryInclude && strings.HasPrefix(c.Name, "remote:"):
		return SecurityChange{
			Severity:    analyze.SeverityHigh,
			Category:    "remote_include_added",
			Description: fmt.Sprintf("New remote include added: %s", c.Name),
			Change:      c,
		}, true
	case c.Type == ChangeRemoved && c.Category == CategoryInclude:
		return SecurityChange{
			Severity:    analyze.SeverityMedium,
			Category:    "include_removed",
			Description: fmt.Sprintf("CI include removed: %s", c.Name),
			Change:      c,
		}, true
	case c.Type == ChangeModified && c.Category == CategoryScript:
		return SecurityChange{
			Severity:    analyze.SeverityMedium,
			Category:    "script_changed",
			Description: fmt.Sprintf("Script content changed in job '%s'", c.Name),
			Change:      c,
		}, true
	case c.Type == ChangeAdded && c.Category == CategoryVariable:
		return SecurityChange{
			Severity:    analyze.SeverityLow,
			Category:    "variable_added",
			Description: fmt.Sprintf("New variable added: %s", c.Name),
			Change:      c,
		}, true
	case c.Type == ChangeRemoved && c.Category == CategoryVariable:
		return SecurityChange{
			Severity:    analyze.SeverityLow,
			Category:    "variable_removed",
			Description: fmt.Sprintf("Variable removed: %s", c.Name),
			Change:      c,
		}, true
	default:
		return SecurityChange{}, false
	}
}

func isSecurityJob(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range securityJobPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
