package analyze

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

// Severity levels for findings.
type Severity string

const (
	SeverityInformational Severity = "INFORMATIONAL"
	SeverityLow           Severity = "LOW"
	SeverityMedium        Severity = "MEDIUM"
	SeverityHigh          Severity = "HIGH"
	SeverityCritical      Severity = "CRITICAL"
)

// AllSeverities lists severity levels in descending order for consistent iteration.
var AllSeverities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational}

// Finding ID constants.
const (
	IncludeRemoteID        = "INCLUDE_REMOTE"
	SecretExfilHTTPID      = "SECRET_EXFIL_HTTP"     //nolint:gosec // finding ID, not a credential
	SecretExfilArtifactID  = "SECRET_EXFIL_ARTIFACT" //nolint:gosec // finding ID, not a credential
	ScriptEncodedPayloadID = "SCRIPT_ENCODED_PAYLOAD"
	WhitespaceHidingID     = "SCRIPT_WHITESPACE_HIDING"
	CharcodeObfuscationID  = "CHARCODE_OBFUSCATION"
	SuspiciousNetworkID    = "SUSPICIOUS_NETWORK_TARGET"
	CampaignMatchID        = "CAMPAIGN_MATCH"
)

// Dependency records a structured cross-project reference extracted during analysis.
type Dependency struct {
	Kind string `json:"kind"` // "project", "remote", "component", "trigger"
	Path string `json:"path"` // project path, URL, or component ref
}

// Finding represents a single analysis result.
type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Evidence       string   `json:"evidence,omitempty"`
	JobName        string   `json:"job_name,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`

	FalsePositive       bool   `json:"false_positive,omitempty"`
	FalsePositiveReason string `json:"false_positive_reason,omitempty"`

	Deps []Dependency `json:"deps,omitempty"`
}

// ErrPartial indicates some checks failed but partial results are returned.
var ErrPartial = errors.New("partial analysis")

// runConfig holds optional behavior toggles for Run.
type runConfig struct {
	redactSecrets bool
	controls      *config.ControlsConfig
	threatIntel   *config.ThreatIntelFeed
}

// Option configures Run behavior.
type Option func(*runConfig)

// WithRedactedSecrets masks plaintext secret values in finding evidence
// (PLAINTEXT_SECRET / PLAINTEXT_SECRET_JOB). The variable name is still shown.
// By default Run leaves these values unredacted.
func WithRedactedSecrets() Option {
	return func(c *runConfig) { c.redactSecrets = true }
}

// WithThreatIntel merges an external threat intelligence feed into network target detection.
func WithThreatIntel(feed *config.ThreatIntelFeed) Option {
	return func(c *runConfig) { c.threatIntel = feed }
}

// WithControls injects per-detection configuration into the analysis engine.
// A nil value is safe and means "use hardcoded defaults".
func WithControls(cfg *config.ControlsConfig) Option {
	return func(c *runConfig) { c.controls = cfg }
}

// Run executes core checks against the parsed CI document.
//
//nolint:gocognit
func Run(doc *pipeline.Document, opts ...Option) ([]Finding, error) {
	if doc == nil {
		return nil, nil
	}
	cfg := runConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	findings := make([]Finding, 0, 64)

	// 0) Workflow-level rules risks
	if workflowRulesAllowBroad(doc.Workflow.Rules) {
		findings = append(findings, Finding{
			ID:          "WORKFLOW_BROAD_RULES",
			Severity:    SeverityInformational,
			Title:       "Workflow has broad rules",
			Description: "Top-level workflow rules appear broad (e.g., when: always). Ensure pipeline is gated appropriately to avoid unintended triggers.",
			Evidence:    toJSONString(doc.Workflow.Rules),
		})
	}

	// 1) Include risks
	for _, inc := range doc.Includes {
		switch inc.Type {
		case pipeline.IncludeRemote:
			findings = append(findings, Finding{
				ID:          IncludeRemoteID,
				Severity:    SeverityHigh,
				Title:       "Remote include in pipeline",
				Description: "Pipeline includes a remote URL. If the remote is compromised or modified, your pipeline can be hijacked. Prefer project includes with pinned refs.",
				Evidence:    fmt.Sprintf("remote=%s", inc.Remote),
				Deps:        []Dependency{{Kind: "remote", Path: inc.Remote}},
			})
		case pipeline.IncludeProject:
			if strings.TrimSpace(inc.Ref) == "" {
				findings = append(findings, Finding{
					ID:          "INCLUDE_PROJECT_UNPINNED",
					Severity:    SeverityHigh,
					Title:       "Unpinned project include",
					Description: "Project include without a ref pin (branch/tag/commit). Changes upstream may silently alter your pipeline.",
					Evidence:    fmt.Sprintf("project=%s files=%v", inc.Project, inc.File),
					Deps:        []Dependency{{Kind: "project", Path: inc.Project}},
				})
			}
		case pipeline.IncludeComponent:
			findings = append(findings, Finding{
				ID:          "INCLUDE_COMPONENT",
				Severity:    SeverityMedium,
				Title:       "CI/CD component include",
				Description: "Pipeline uses a CI/CD component. Ensure the component source is trusted and pinned.",
				Evidence:    fmt.Sprintf("component=%s", inc.Component),
				Deps:        []Dependency{{Kind: "component", Path: inc.Component}},
			})
		}
	}

	// 2) Job trigger risks and runner exposure
	for _, job := range doc.Jobs {
		// Self-hosted runner tags suggest sensitive runners
		if len(job.Tags) > 0 {
			if jobRulesAllowBroad(job.Rules) || onlyIsBroad(job.Only) {
				sev := SeverityHigh
				// If rules include fork/protected guards, downgrade severity to medium to reduce FPs
				if checkForkProtection(job.Rules) {
					sev = SeverityMedium
				}
				findings = append(findings, Finding{
					ID:          "SELF_HOSTED_EXPOSED",
					Severity:    sev,
					Title:       "Job on tagged runner with broad triggers",
					Description: "Job targets specific runner tags and is broadly triggerable (e.g., when: always or wide refs). This can enable runner takeover.",
					Evidence:    fmt.Sprintf("tags=%v", job.Tags),
					JobName:     job.Name,
				})
			}
		}
		// Merge Request triggered jobs with tagged runners
		if (jobTriggersOnMR(job) || triggersOnMRViaOnly(job.Only)) && len(job.Tags) > 0 {
			sev := SeverityMedium
			if checkForkProtection(job.Rules) {
				// Protections present; lower severity to reduce false positives
				sev = SeverityLow
			}
			findings = append(findings, Finding{
				ID:          "MR_TAGGED_RUNNER",
				Severity:    sev,
				Title:       "MR-triggered job on tagged runner",
				Description: "Job triggers on merge_request_event (rules/only) and uses tagged runners. Ensure the job is safe for fork MRs or restrict with protected conditions/approval.",
				Evidence:    fmt.Sprintf("tags=%v", job.Tags),
				JobName:     job.Name,
			})
		}
	}

	// 2b) Risky remote script execution in job scripts (before, script, after)
	for _, job := range doc.Jobs {
		for _, line := range effectiveScripts(job, doc) {
			if isRiskyRemoteScript(line) {
				findings = append(findings, Finding{
					ID:          "RISKY_REMOTE_SCRIPT",
					Severity:    SeverityMedium,
					Title:       "Job executes remote script content",
					Description: "Script downloads code from the network and executes it directly (e.g., curl|bash, wget|sh, PowerShell iwr|iex). This is risky unless the source is fully trusted and pinned.",
					Evidence:    stringutil.TruncateEvidence(line, 160),
					JobName:     job.Name,
				})
			}
		}
	}

	// 2c) Artifacts without expire_in (unbounded retention)
	for _, job := range doc.Jobs {
		if job.Artifacts != nil {
			exp, hasExpire := job.Artifacts["expire_in"]
			if !hasExpire || strings.TrimSpace(fmt.Sprintf("%v", exp)) == "" {
				findings = append(findings, Finding{
					ID:          "ARTIFACTS_NO_EXPIRE",
					Severity:    SeverityInformational,
					Title:       "Artifacts do not specify expire_in",
					Description: "Job defines artifacts without an expire_in. This can keep artifacts indefinitely, increasing exfiltration risk and storage cost. Set expire_in unless long retention is strictly required.",
					Evidence:    toJSONString(job.Artifacts),
					JobName:     job.Name,
				})
			}
		}
	}

	// 3) Suspicious plaintext variables
	for k, v := range doc.Variables {
		if s, ok := v.(string); ok {
			if looksLikeSecretKey(k, s) {
				val := s
				if cfg.redactSecrets {
					val = "<redacted>"
				}
				findings = append(findings, Finding{
					ID:          "PLAINTEXT_SECRET",
					Severity:    SeverityMedium,
					Title:       "Suspicious plaintext variable",
					Description: "Variable name looks secret-like and contains plaintext. Consider using masked, protected variables and avoid committing secrets.",
					Evidence:    fmt.Sprintf("%s=%s", k, val),
				})
			}
		}
	}
	for _, job := range doc.Jobs {
		for k, v := range job.Variables {
			if s, ok := v.(string); ok {
				if looksLikeSecretKey(k, s) {
					val := s
					if cfg.redactSecrets {
						val = "<redacted>"
					}
					findings = append(findings, Finding{
						ID:          "PLAINTEXT_SECRET_JOB",
						Severity:    SeverityMedium,
						Title:       "Suspicious plaintext variable at job level",
						Description: "Job-level variable name looks secret-like and contains plaintext.",
						Evidence:    fmt.Sprintf("%s=%s (job=%s)", k, val, job.Name),
						JobName:     job.Name,
					})
				}
			}
		}
	}

	// Steps 4–32: detection functions registered as a step table.
	// Each step wraps a detect* function; closures capture cfg fields
	// when the underlying function needs extra arguments.
	type detectionStep struct {
		name string
		fn   func(*pipeline.Document) []Finding
	}
	steps := []detectionStep{
		{"variable_injection", func(d *pipeline.Document) []Finding { return detectVariableInjection(d) }},
		{"fork_mr_risks", func(d *pipeline.Document) []Finding { return detectForkMRRisks(d) }},
		{"fork_script_execution", func(d *pipeline.Document) []Finding { return detectForkScriptExecution(d) }},
		{"artifact_poisoning", func(d *pipeline.Document) []Finding { return detectArtifactPoisoning(d) }},
		{"dispatch_toctou", func(d *pipeline.Document) []Finding { return detectDispatchTOCTOU(d) }},
		{"pwn_request_nuances", func(d *pipeline.Document) []Finding { return detectPwnRequestNuances(d) }},
		{"privileged_runner_use", func(d *pipeline.Document) []Finding { return detectPrivilegedRunnerUse(d) }},
		{"ai_prompt_injection", func(d *pipeline.Document) []Finding { return detectAIPromptInjection(d) }},
		{"script_injection_risk", func(d *pipeline.Document) []Finding { return detectScriptInjectionRisk(d) }},
		{"self_merge_possible", func(d *pipeline.Document) []Finding { return detectSelfMergePossible(d) }},
		{"cache_poisoning_risk", func(d *pipeline.Document) []Finding { return detectCachePoisoningRisk(d) }},
		{"lotp_tool_exec", func(d *pipeline.Document) []Finding { return detectLOTPToolExec(d) }},
		{"cache_key_injection", func(d *pipeline.Document) []Finding { return detectCacheKeyInjection(d) }},
		{"oidc_token_mr_risk", func(d *pipeline.Document) []Finding { return detectOIDCTokenMRRisk(d) }},
		{"trigger_chain_risk", func(d *pipeline.Document) []Finding { return detectTriggerChainRisk(d) }},
		{"debug_trace", func(d *pipeline.Document) []Finding { return detectDebugTrace(d, cfg.controls) }},
		{"unverified_script_exec", func(d *pipeline.Document) []Finding { return detectUnverifiedScriptExec(d) }},
		{"unpinned_package_install", func(d *pipeline.Document) []Finding { return detectUnpinnedPackageInstall(d) }},
		{"governance", func(d *pipeline.Document) []Finding { return detectGovernance(d, cfg.controls) }},
		{"dind", func(d *pipeline.Document) []Finding { return detectDinD(d) }},
		{"image_issues", func(d *pipeline.Document) []Finding { return detectImageIssues(d, cfg.controls) }},
		{"script_obfuscation", func(d *pipeline.Document) []Finding { return detectScriptObfuscation(d) }},
		{"secret_exfiltration", func(d *pipeline.Document) []Finding { return detectSecretExfiltration(d) }},
		{"encoded_payloads", func(d *pipeline.Document) []Finding { return detectEncodedPayloads(d) }},
		{"suspicious_network_targets", func(d *pipeline.Document) []Finding { return detectSuspiciousNetworkTargets(d, cfg.threatIntel) }},
		{"campaign_signatures", func(d *pipeline.Document) []Finding { return detectCampaignSignatures(d) }},
		{"workflow_secret_exfil", func(d *pipeline.Document) []Finding { return detectWorkflowSecretExfil(d) }},
		{"dependency_confusion", func(d *pipeline.Document) []Finding { return detectDependencyConfusion(d) }},
		{"ai_config_harvesters", func(d *pipeline.Document) []Finding { return detectAIConfigHarvesters(d) }},
		{"oidc_provenance_anomaly", func(d *pipeline.Document) []Finding { return detectOIDCProvenanceAnomaly(d) }},
	}
	for _, s := range steps {
		findings = append(findings, s.fn(doc)...)
	}

	// Filter disabled rules
	if cfg.controls != nil {
		var filtered []Finding
		for _, f := range findings {
			if !cfg.controls.IsRuleDisabled(f.ID) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Attach basic recommendations
	findings = withRecommendations(findings)
	return findings, nil
}

// withRecommendations attaches a recommendation string from the codes registry.
func withRecommendations(in []Finding) []Finding {
	for i := range in {
		if strings.TrimSpace(in[i].Recommendation) != "" {
			continue
		}
		if info := LookupFinding(in[i].ID); info != nil {
			in[i].Recommendation = info.Remediation
		} else {
			in[i].Recommendation = defaultRemediation //nolint:gosec // G602: i bounded by range
		}
	}
	return in
}

// extractVarValue extracts the string value from a CI variable that may use
// GitLab's expanded syntax: {value: "...", description: "..."}.
// Returns (stringValue, true) if the variable exists, ("", false) otherwise.
func extractVarValue(raw any) (string, bool) {
	if raw == nil {
		return "", false
	}
	if s, ok := raw.(string); ok {
		return s, true
	}
	if m, ok := raw.(map[string]any); ok {
		if v, exists := m["value"]; exists {
			if s, ok := v.(string); ok {
				return s, true
			}
			return fmt.Sprintf("%v", v), true
		}
	}
	return fmt.Sprintf("%v", raw), true
}

// effectiveScripts returns the full ordered set of script lines a job will run:
// before_script (job-level overrides global) + script + after_script (job-level overrides global).
// This is the correct scope for injection and LOTP analysis.
func effectiveScripts(job pipeline.Job, doc *pipeline.Document) []string {
	var lines []string
	before := job.BeforeScript
	if before == nil {
		before = doc.BeforeScript
	}
	lines = append(lines, before...)
	lines = append(lines, job.Script...)
	after := job.AfterScript
	if after == nil {
		after = doc.AfterScript
	}
	lines = append(lines, after...)
	return lines
}

// isRiskyRemoteScript returns true if the script line appears to download code and execute it directly.
func isRiskyRemoteScript(s string) bool {
	line := strings.ToLower(strings.TrimSpace(s))
	if line == "" {
		return false
	}
	// Common bash/sh pipe patterns
	if strings.Contains(line, "curl") {
		if strings.Contains(line, "| bash") || strings.Contains(line, "|bash") || strings.Contains(line, "| sh") || strings.Contains(line, "|sh") {
			return true
		}
		// generic $(curl ...)
		if strings.Contains(line, "$(curl") || strings.Contains(line, "bash -c \"$(curl") {
			return true
		}
		// process substitution
		if strings.Contains(line, "<(curl") {
			return true
		}
	}
	if strings.Contains(line, "wget") {
		if strings.Contains(line, "| bash") || strings.Contains(line, "|bash") || strings.Contains(line, "| sh") || strings.Contains(line, "|sh") {
			return true
		}
		// generic $(wget ...)
		if strings.Contains(line, "$(wget") || strings.Contains(line, "bash -c \"$(wget") {
			return true
		}
	}
	// PowerShell patterns
	if strings.Contains(line, "powershell") || strings.Contains(line, "pwsh") || strings.Contains(line, "iwr") || strings.Contains(line, "irm") || strings.Contains(line, "invoke-webrequest") || strings.Contains(line, "invoke-restmethod") {
		if strings.Contains(line, "| iex") || strings.Contains(line, "|iex") || strings.Contains(line, "invoke-expression") {
			return true
		}
	}
	return false
}

func jobRulesAllowBroad(rules any) bool {
	if rules == nil {
		return false
	}
	// Quick heuristic: stringify and search for risk markers
	text := toJSONString(rules)
	textLow := strings.ToLower(text)
	return strings.Contains(textLow, "when\":\"always\"") || strings.Contains(textLow, "when: always")
}

func jobTriggersOnMR(rules any) bool {
	if rules == nil {
		return false
	}
	// Prefer structural evaluation of rules:if with an MR context
	ctx := map[string]string{"CI_PIPELINE_SOURCE": "merge_request_event"}
	if rulesRunInContext(rules, ctx) {
		return true
	}
	// Fallback heuristic for non-standard encodings
	text := strings.ToLower(toJSONString(rules))
	return strings.Contains(text, "merge_request_event") || strings.Contains(text, "ci_pipeline_source == 'merge_request_event'")
}

func onlyIsBroad(only any) bool {
	switch t := only.(type) {
	case []any:
		for _, it := range t {
			if s, ok := it.(string); ok {
				if s == "branches" || s == "*" || strings.Contains(s, ".*") {
					return true
				}
			}
		}
	case map[string]any:
		if refs, ok := t["refs"]; ok {
			return onlyIsBroad(refs)
		}
	}
	return false
}

// triggersOnMRViaOnly returns true if legacy only/except config indicates MR pipelines.
func triggersOnMRViaOnly(only any) bool {
	switch t := only.(type) {
	case []any:
		for _, it := range t {
			if s, ok := it.(string); ok {
				if s == "merge_requests" || s == "merge_request" || s == "external_pull_requests" { // last one unlikely on GitLab, but safe
					return true
				}
			}
		}
	case map[string]any:
		if refs, ok := t["refs"]; ok {
			return triggersOnMRViaOnly(refs)
		}
	}
	return false
}

func toJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		slog.Debug("json marshal failed in evidence", "error", err)
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func looksLikeSecretKey(name, val string) bool {
	lname := strings.ToUpper(name)
	if strings.Contains(lname, "SECRET") || strings.Contains(lname, "TOKEN") || strings.Contains(lname, "KEY") || strings.Contains(lname, "PASSWORD") {
		// If value looks obviously non-empty and not a reference
		if val != "" && !strings.HasPrefix(val, "${") && !strings.HasPrefix(val, "$CI_") {
			return true
		}
	}
	// Some pattern hints
	if strings.HasPrefix(val, "AKIA") || strings.HasPrefix(val, "ghp_") || strings.HasPrefix(val, "glpat-") || strings.HasPrefix(val, "eyJ") {
		return true
	}
	return false
}

// workflowRulesAllowBroad returns true if workflow: rules look broadly permissive (e.g., when: always).
func workflowRulesAllowBroad(rules any) bool {
	return jobRulesAllowBroad(rules)
}
