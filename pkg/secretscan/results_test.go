package secretscan

import "testing"

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short", "abc", "****"},
		{"exactly_12", "abcdefghijkl", "abcd****ijkl"},
		{"long", "ghp_1234567890abcdef", "ghp_****cdef"},
		{"11_chars", "12345678901", "****"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactSecret(tt.in)
			if got != tt.want {
				t.Errorf("RedactSecret(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactFindings(t *testing.T) {
	findings := []SecretFinding{
		{Secret: "ghp_1234567890abcdef", Scanner: "gitleaks"},
		{Secret: "short", Scanner: "trufflehog"},
		{Secret: "", Scanner: "titus"},
	}
	redacted := RedactFindings(findings)

	if redacted[0].Secret != "ghp_****cdef" {
		t.Errorf("expected redacted long secret, got %q", redacted[0].Secret)
	}
	if redacted[1].Secret != "****" {
		t.Errorf("expected fully masked short secret, got %q", redacted[1].Secret)
	}
	if redacted[2].Secret != "" {
		t.Errorf("expected empty secret to remain empty, got %q", redacted[2].Secret)
	}

	// Verify original is not mutated
	if findings[0].Secret != "ghp_1234567890abcdef" {
		t.Error("original findings were mutated")
	}
}

func TestBuildSummary(t *testing.T) {
	results := []ScanResult{
		{
			FindingsCount: 2,
			Findings: []SecretFinding{
				{Scanner: "gitleaks", Severity: "HIGH"},
				{Scanner: "trufflehog", Severity: "LOW"},
			},
		},
		{FindingsCount: 0},
		{
			FindingsCount: 1,
			Findings: []SecretFinding{
				{Scanner: "gitleaks", Severity: "HIGH"},
			},
		},
	}

	s := BuildSummary(results)

	if s.TotalProjects != 3 {
		t.Errorf("TotalProjects = %d, want 3", s.TotalProjects)
	}
	if s.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", s.TotalFindings)
	}
	if s.ProjectsWithFindings != 2 {
		t.Errorf("ProjectsWithFindings = %d, want 2", s.ProjectsWithFindings)
	}
	if s.ByScanner["gitleaks"] != 2 {
		t.Errorf("ByScanner[gitleaks] = %d, want 2", s.ByScanner["gitleaks"])
	}
	if s.BySeverity["HIGH"] != 2 {
		t.Errorf("BySeverity[HIGH] = %d, want 2", s.BySeverity["HIGH"])
	}
}
