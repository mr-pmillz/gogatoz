package payloads

import (
	"strings"
	"testing"
)

func TestGenerateNeedsProjectYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     NeedsProjectOptions
		contains []string
	}{
		{
			name: "default needs project",
			opts: NeedsProjectOptions{},
			contains: []string{
				"needs:",
				"project: attacker/compromised-lib",
				"job: build",
				"ref: main",
				"artifacts: true",
				"_EXPLOIT()",
				"_EXPLOIT || true",
				"allow_failure: true",
			},
		},
		{
			name: "custom source project",
			opts: NeedsProjectOptions{
				Common:        CommonOptions{JobName: "inject"},
				SourceProject: "acme/shared-lib",
				SourceRef:     "v2.0.0",
				SourceJob:     "package",
			},
			contains: []string{
				"inject:",
				"project: acme/shared-lib",
				"ref: v2.0.0",
				"job: package",
			},
		},
		{
			name: "custom poison script",
			opts: NeedsProjectOptions{
				PoisonScript: "cat secrets.json || true",
			},
			contains: []string{
				"cat secrets.json",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateNeedsProjectYAML(tc.opts)
			for _, s := range tc.contains {
				if !strings.Contains(y, s) {
					t.Errorf("expected %q in output:\n%s", s, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
