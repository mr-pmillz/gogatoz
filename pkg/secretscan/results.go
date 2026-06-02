// Package secretscan clones GitLab projects and scans them for secrets
// using external CLI tools (TruffleHog, Gitleaks, Titus).
package secretscan

// ScanResult captures the outcome for a single project scanned by one or more tools.
type ScanResult struct {
	GitLabProjectID   int64           `json:"project_id"`
	PathWithNamespace string          `json:"path_with_namespace"`
	WebURL            string          `json:"web_url"`
	ClonePath         string          `json:"clone_path,omitempty"`
	Scanners          []string        `json:"scanners"`
	Findings          []SecretFinding `json:"findings,omitempty"`
	FindingsCount     int             `json:"findings_count"`
	DurationMS        int64           `json:"duration_ms"`
	Error             string          `json:"error,omitempty"`
}

// SecretFinding represents a single secret detected by an external scanner.
type SecretFinding struct {
	Scanner     string  `json:"scanner"`
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description,omitempty"`
	File        string  `json:"file"`
	Line        int     `json:"line,omitempty"`
	Secret      string  `json:"secret,omitempty"` //nolint:gosec // secret value from scanner output, not a credential
	Entropy     float64 `json:"entropy,omitempty"`
	Commit      string  `json:"commit,omitempty"`
	Author      string  `json:"author,omitempty"`
	Date        string  `json:"date,omitempty"`
	Verified    bool    `json:"verified,omitempty"`
	Severity    string  `json:"severity,omitempty"`
}

// Summary aggregates statistics across all scanned projects.
type Summary struct {
	TotalProjects        int            `json:"total_projects"`
	TotalFindings        int            `json:"total_findings"`
	ProjectsWithFindings int            `json:"projects_with_findings"`
	ByScanner            map[string]int `json:"by_scanner"`
	BySeverity           map[string]int `json:"by_severity,omitempty"`
}

// BuildSummary computes aggregate stats from a slice of scan results.
func BuildSummary(results []ScanResult) Summary {
	s := Summary{
		TotalProjects: len(results),
		ByScanner:     make(map[string]int),
		BySeverity:    make(map[string]int),
	}
	for _, r := range results {
		s.TotalFindings += r.FindingsCount
		if r.FindingsCount > 0 {
			s.ProjectsWithFindings++
		}
		for _, f := range r.Findings {
			s.ByScanner[f.Scanner]++
			if f.Severity != "" {
				s.BySeverity[f.Severity]++
			}
		}
	}
	return s
}

// RedactSecret masks the middle of a secret, showing only the first 4 and
// last 4 characters. Secrets shorter than 12 characters are fully masked.
func RedactSecret(s string) string {
	if len(s) == 0 {
		return s
	}
	if len(s) < 12 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// RedactFindings returns a copy of findings with all Secret fields redacted.
func RedactFindings(findings []SecretFinding) []SecretFinding {
	out := make([]SecretFinding, len(findings))
	copy(out, findings)
	for i := range out {
		out[i].Secret = RedactSecret(out[i].Secret)
	}
	return out
}
