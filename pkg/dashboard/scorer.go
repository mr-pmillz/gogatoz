package dashboard

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

// ProjectScorecard captures the security posture score for a single project.
type ProjectScorecard struct {
	ProjectPath          string         `json:"project_path"`
	Score                int            `json:"score"`
	RiskTier             string         `json:"risk_tier"`
	FindingsBySeverity   map[string]int `json:"findings_by_severity"`
	HasCI                bool           `json:"has_ci"`
	HasSecurityJobs      bool           `json:"has_security_jobs"`
	HasProtectedBranches bool           `json:"has_protected_branches"`
}

// securityJobPatterns are substrings that indicate a job performs security scanning.
var securityJobPatterns = []string{
	"sast", "dast", "secret", "dependency", "container_scan",
	"license_scan", "security", "semgrep", "trivy", "bandit",
}

// ScoreProject computes a security scorecard for a single enumerate result.
//
// Scoring algorithm:
//   - Start at 100
//   - Deduct per non-FP finding: Critical -15, High -8, Medium -3, Low -1
//   - Bonus: +5 for security scanning jobs, +5 for protected default branch
//   - Floor 0, cap 100
//   - Tiers: Critical (0-20), High (21-40), Medium (41-60), Low (61-80), Clean (81-100)
func ScoreProject(r enumerate.Result) ProjectScorecard {
	sc := ProjectScorecard{
		ProjectPath:          r.ProjectPathWithNS,
		HasCI:                r.HasCIPipeline,
		HasProtectedBranches: len(r.ProtectedBranches) > 0,
		FindingsBySeverity:   map[string]int{},
	}

	score := 100
	for _, f := range r.Findings {
		if f.FalsePositive {
			continue
		}
		sc.FindingsBySeverity[string(f.Severity)]++
		switch f.Severity {
		case analyze.SeverityCritical:
			score -= 15
		case analyze.SeverityHigh:
			score -= 8
		case analyze.SeverityMedium:
			score -= 3
		case analyze.SeverityLow:
			score -= 1
		}
	}

	// Check for security scanning jobs by inspecting job names in findings.
	for _, f := range r.Findings {
		lower := strings.ToLower(f.JobName)
		for _, pat := range securityJobPatterns {
			if strings.Contains(lower, pat) {
				sc.HasSecurityJobs = true
				break
			}
		}
		if sc.HasSecurityJobs {
			break
		}
	}

	if sc.HasSecurityJobs {
		score += 5
	}
	if sc.HasProtectedBranches {
		score += 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	sc.Score = score

	switch {
	case score <= 20:
		sc.RiskTier = "Critical"
	case score <= 40:
		sc.RiskTier = "High"
	case score <= 60:
		sc.RiskTier = "Medium"
	case score <= 80:
		sc.RiskTier = "Low"
	default:
		sc.RiskTier = "Clean"
	}

	return sc
}
