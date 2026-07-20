package payloads

import (
	"strings"
	"testing"
)

func TestGenerateParallelMatrixYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     ParallelMatrixOptions
		contains []string
		absent   []string
	}{
		{
			name: "default matrix",
			opts: ParallelMatrixOptions{},
			contains: []string{
				"parallel:",
				"matrix:",
				"TARGET_PATH:",
				"EXFIL_METHOD:",
				"/proc/self/environ",
				"_SWEEP()",
				"_SWEEP || true",
				"allow_failure: true",
			},
			absent: []string{
				"curl",
			},
		},
		{
			name: "custom matrix vars",
			opts: ParallelMatrixOptions{
				Common: CommonOptions{JobName: "brute-force"},
				MatrixVars: map[string][]string{
					"API_KEY": {"key1", "key2", "key3"},
					"REGION":  {"us-east-1", "eu-west-1"},
				},
			},
			contains: []string{
				"brute-force:",
				"API_KEY:",
				"REGION:",
				`"key1"`,
				`"us-east-1"`,
			},
		},
		{
			name: "with callback URL",
			opts: ParallelMatrixOptions{
				CallbackURL: "https://attacker.com/c2",
			},
			contains: []string{
				"curl",
				"https://attacker.com/c2/exfil",
				"$CI_NODE_INDEX",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateParallelMatrixYAML(tc.opts)
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
