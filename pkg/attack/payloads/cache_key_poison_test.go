package payloads

import (
	"strings"
	"testing"
)

func TestGenerateCacheKeyPoisonYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     CacheKeyPoisonOptions
		contains []string
		absent   []string
	}{
		{
			name: "default options",
			opts: CacheKeyPoisonOptions{},
			contains: []string{
				"cache:",
				`key: "$CI_DEFAULT_BRANCH"`,
				"policy: push",
				".cache",
				"node_modules",
				"vendor",
				"_POISON()",
				"_POISON || true",
				"allow_failure: true",
			},
		},
		{
			name: "custom prefix",
			opts: CacheKeyPoisonOptions{
				Common:    CommonOptions{JobName: "poison-cache"},
				KeyPrefix: "$CI_COMMIT_REF_SLUG",
				Policy:    "pull-push",
			},
			contains: []string{
				"poison-cache:",
				`key: "$CI_COMMIT_REF_SLUG"`,
				"policy: pull-push",
			},
		},
		{
			name: "with key files",
			opts: CacheKeyPoisonOptions{
				KeyPrefix: "shared",
				KeyFiles:  []string{"Gemfile.lock", "package-lock.json"},
			},
			contains: []string{
				"key:",
				`prefix: "shared"`,
				"files:",
				"- Gemfile.lock",
				"- package-lock.json",
			},
		},
		{
			name: "custom poison command",
			opts: CacheKeyPoisonOptions{
				CachePaths: []string{".pip-cache"},
				PoisonCmd:  "echo 'malicious' > .pip-cache/setup.py",
			},
			contains: []string{
				"- .pip-cache",
				"echo 'malicious' > .pip-cache/setup.py",
			},
			absent: []string{
				"_POISON()",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateCacheKeyPoisonYAML(tc.opts)
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
