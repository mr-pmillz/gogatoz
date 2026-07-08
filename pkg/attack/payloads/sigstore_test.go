package payloads

import (
	"strings"
	"testing"
)

func TestGenerateSigstoreYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     SigstoreOptions
		contains []string
	}{
		{
			name: "default options",
			opts: SigstoreOptions{},
			contains: []string{
				"stages:",
				"sigstore-forge:",
				"node:lts-alpine",
				"Fulcio",
				"Rekor",
				"DSSE",
				"sigstore",
				"ecparam",
				"OIDC",
				"target-package",
				"1.0.0",
				"https://registry.npmjs.org",
				"prime256v1",
				"slsa.dev/provenance/v1",
				"in-toto",
				"bundle.v0.3",
			},
		},
		{
			name: "custom package and version",
			opts: SigstoreOptions{
				Common:      CommonOptions{JobName: "forge-pkg", Tags: []string{"shared"}},
				PackageName: "lodash",
				Version:     "4.17.21",
				RegistryURL: "https://custom-registry.example.com",
				CallbackURL: "https://attacker.example.com/collect",
			},
			contains: []string{
				"forge-pkg:",
				"lodash",
				"4.17.21",
				"https://custom-registry.example.com",
				"https://attacker.example.com/collect",
				"Fulcio",
				"Rekor",
				"DSSE",
				"ecparam",
				"sigstore",
			},
		},
		{
			name: "custom image override",
			opts: SigstoreOptions{
				Common: CommonOptions{Image: "alpine:3.19"},
			},
			contains: []string{
				"alpine:3.19",
				"Fulcio",
				"Rekor",
			},
		},
		{
			name: "manual rule",
			opts: SigstoreOptions{
				Common: CommonOptions{Manual: true},
			},
			contains: []string{
				"when: manual",
				"DSSE",
				"sigstore",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateSigstoreYAML(tt.opts)

			for _, substr := range tt.contains {
				if !strings.Contains(y, substr) {
					t.Errorf("expected %q in output:\n%s", substr, y)
				}
			}

			_ = mustParse(t, y)
		})
	}
}
