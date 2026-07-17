package payloads

import (
	"strings"
	"testing"
)

func TestGenerateInterruptibleAttackYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     InterruptibleOptions
		contains []string
		absent   []string
	}{
		{
			name: "default interruptible attack",
			opts: InterruptibleOptions{},
			contains: []string{
				"stages: [setup, trigger, exploit]",
				"critical-setup:",
				"interruptible: true",
				"sleep 30",
				"when: on_failure",
				"interruptible-exploit-trigger:",
				"interruptible-exploit:",
				"_FALLBACK()",
				"_FALLBACK || true",
				"curl",
				"allow_failure: true",
			},
		},
		{
			name: "custom target jobs",
			opts: InterruptibleOptions{
				Common:     CommonOptions{JobName: "race-attack"},
				TargetJobs: []string{"init-deps", "setup-creds", "configure-env"},
			},
			contains: []string{
				"init-deps:",
				"setup-creds:",
				"configure-env:",
				"interruptible: true",
				"race-attack-trigger:",
				"race-attack:",
			},
		},
		{
			name: "custom fallback with tags",
			opts: InterruptibleOptions{
				Common:         CommonOptions{Tags: []string{"self-hosted"}, Manual: true},
				FallbackScript: "echo 'exploiting interrupted state'",
			},
			contains: []string{
				"tags:",
				"self-hosted",
				"echo 'exploiting interrupted state'",
				"when: manual",
			},
			absent: []string{
				"_FALLBACK()",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateInterruptibleAttackYAML(tc.opts)
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
