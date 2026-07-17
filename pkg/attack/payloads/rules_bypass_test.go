package payloads

import (
	"strings"
	"testing"
)

func TestGenerateRulesBypassYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     RulesBypassOptions
		contains []string
		absent   []string
	}{
		{
			name: "default bypass",
			opts: RulesBypassOptions{},
			contains: []string{
				"sast:",
				"dast:",
				"secret_detection:",
				"nonexistent-path-",
				"nonexistent-sentinel-",
				"code-quality-check:",
				"printenv | sort",
			},
		},
		{
			name: "custom bypassed jobs",
			opts: RulesBypassOptions{
				BypassedJobs:    []string{"container_scanning", "license_management"},
				AttackerJobName: "lint-check",
			},
			contains: []string{
				"container_scanning:",
				"license_management:",
				"lint-check:",
			},
			absent: []string{
				"sast:",
				"dast:",
			},
		},
		{
			name: "custom match paths",
			opts: RulesBypassOptions{
				MatchPaths: []string{"Makefile", "Dockerfile"},
			},
			contains: []string{
				"Makefile",
				"Dockerfile",
			},
		},
		{
			name: "with tags",
			opts: RulesBypassOptions{
				Common: CommonOptions{Tags: []string{"self-hosted"}},
			},
			contains: []string{
				"tags:",
				"self-hosted",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateRulesBypassYAML(tc.opts)
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
