package secretsdump

// Common redaction keys seen in logs and artifacts that should be ignored.
const (
	RedactionKeyMasked   = "MASKED"
	RedactionKeyJobJWT   = "CI_JOB_JWT"
	RedactionKeyJobToken = "CI_JOB_TOKEN" //nolint:gosec
)
