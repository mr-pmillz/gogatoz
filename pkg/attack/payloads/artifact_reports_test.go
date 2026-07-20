package payloads

import (
	"strings"
	"testing"
)

func TestGenerateArtifactReportsYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     ArtifactReportsOptions
		contains []string
		absent   []string
	}{
		{
			name: "default SARIF report",
			opts: ArtifactReportsOptions{},
			contains: []string{
				"artifacts:",
				"reports:",
				"sast: gl-sast-report.json",
				"sarif-schema-2.1.0",
				`"results": []`,
				"_INJECT_REPORT()",
				"_INJECT_REPORT || true",
				"allow_failure: true",
			},
			absent: []string{
				"curl",
			},
		},
		{
			name: "dependency scanning report",
			opts: ArtifactReportsOptions{
				Common:     CommonOptions{JobName: "dep-scan-override"},
				ReportType: "dependency_scanning",
			},
			contains: []string{
				"dep-scan-override:",
				"dependency_scanning: gl-dependency-scanning-report.json",
				`"vulnerabilities": []`,
				`"type": "dependency_scanning"`,
			},
		},
		{
			name: "secret detection report",
			opts: ArtifactReportsOptions{
				ReportType: "secret_scanning",
			},
			contains: []string{
				"secret_detection: gl-secret-detection-report.json",
				`"type": "secret_scanning"`,
			},
		},
		{
			name: "with callback URL",
			opts: ArtifactReportsOptions{
				CallbackURL: "https://attacker.com/c2",
			},
			contains: []string{
				"curl",
				"https://attacker.com/c2/exfil",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateArtifactReportsYAML(tc.opts)
			for _, s := range tc.contains {
				if !strings.Contains(y, s) {
					t.Errorf("expected %q in output:\n%s", s, y)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(y, s) {
					t.Errorf("unexpected %q in output:\n%s", s, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
