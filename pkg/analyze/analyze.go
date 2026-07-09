package analyze

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
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
	IncludeRemoteID = "INCLUDE_REMOTE"
)

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
}

// ErrPartial indicates some checks failed but partial results are returned.
var ErrPartial = errors.New("partial analysis")

// runConfig holds optional behavior toggles for Run.
type runConfig struct {
	redactSecrets bool
	controls      *config.ControlsConfig
}

// Option configures Run behavior.
type Option func(*runConfig)

// WithRedactedSecrets masks plaintext secret values in finding evidence
// (PLAINTEXT_SECRET / PLAINTEXT_SECRET_JOB). The variable name is still shown.
// By default Run leaves these values unredacted.
func WithRedactedSecrets() Option {
	return func(c *runConfig) { c.redactSecrets = true }
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
	var findings []Finding

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
			})
		case pipeline.IncludeProject:
			if strings.TrimSpace(inc.Ref) == "" {
				findings = append(findings, Finding{
					ID:          "INCLUDE_PROJECT_UNPINNED",
					Severity:    SeverityHigh,
					Title:       "Unpinned project include",
					Description: "Project include without a ref pin (branch/tag/commit). Changes upstream may silently alter your pipeline.",
					Evidence:    fmt.Sprintf("project=%s files=%v", inc.Project, inc.File),
				})
			}
		case pipeline.IncludeComponent:
			findings = append(findings, Finding{
				ID:          "INCLUDE_COMPONENT",
				Severity:    SeverityMedium,
				Title:       "CI/CD component include",
				Description: "Pipeline uses a CI/CD component. Ensure the component source is trusted and pinned.",
				Evidence:    fmt.Sprintf("component=%s", inc.Component),
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
					Evidence:    truncateEvidence(line, 160),
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

	// 4) Variable injection detection
	injectionFindings := detectVariableInjection(doc)
	findings = append(findings, injectionFindings...)

	// 5) Fork MR safety checks
	forkFindings := detectForkMRRisks(doc)
	findings = append(findings, forkFindings...)

	// 5b) Fork MR script execution risks
	forkScriptFindings := detectForkScriptExecution(doc)
	findings = append(findings, forkScriptFindings...)

	// 6) Artifact poisoning detection
	artifactFindings := detectArtifactPoisoning(doc)
	findings = append(findings, artifactFindings...)

	// 7) Dispatch/TOCTOU risks (manual jobs, triggers, schedules with broad scope)
	dispatchFindings := detectDispatchTOCTOU(doc)
	findings = append(findings, dispatchFindings...)

	// 8) Pwn Request nuances for deployments without protections
	pwnFindings := detectPwnRequestNuances(doc)
	findings = append(findings, pwnFindings...)

	// 9) Privileged runner usage on MR (e.g., docker:dind)
	privFindings := detectPrivilegedRunnerUse(doc)
	findings = append(findings, privFindings...)

	// 10) AI prompt injection risks
	aiFindings := detectAIPromptInjection(doc)
	findings = append(findings, aiFindings...)

	// 11) Script injection risk (external scripts in MR-triggered jobs)
	scriptInjFindings := detectScriptInjectionRisk(doc)
	findings = append(findings, scriptInjFindings...)

	// 12) Self-merge possible (no approval enforcement detected)
	selfMergeFindings := detectSelfMergePossible(doc)
	findings = append(findings, selfMergeFindings...)

	// 13) Cache poisoning risk (MR-triggered jobs with push cache policy)
	cachePoisonFindings := detectCachePoisoningRisk(doc)
	findings = append(findings, cachePoisonFindings...)

	// 14) LOTP: config-file-based RCE via build/lint tools in MR-triggered jobs
	findings = append(findings, detectLOTPToolExec(doc)...)

	// 15) Cache key injection via attacker-controllable CI variables
	findings = append(findings, detectCacheKeyInjection(doc)...)

	// 16) GitLab OIDC token exposed to MR-triggered jobs
	findings = append(findings, detectOIDCTokenMRRisk(doc)...)

	// 17) Downstream trigger chain abuse in MR-triggered jobs
	findings = append(findings, detectTriggerChainRisk(doc)...)

	// 18) CI debug trace / debug services enabled (secret exposure)
	findings = append(findings, detectDebugTrace(doc, cfg.controls)...)

	// 19) Unverified script execution (base64|bash, download-then-exec)
	findings = append(findings, detectUnverifiedScriptExec(doc)...)

	// 20) Unpinned package installs (supply chain risk)
	findings = append(findings, detectUnpinnedPackageInstall(doc)...)

	// 21) Pipeline governance (mutable include refs, weakened security jobs)
	findings = append(findings, detectGovernance(doc, cfg.controls)...)

	// 22) Docker-in-Docker detection (container escape risk)
	findings = append(findings, detectDinD(doc)...)

	// 23) Container image supply chain (mutable tags, missing digest pins)
	findings = append(findings, detectImageIssues(doc, cfg.controls)...)

	// 24) Script obfuscation (zero-width chars, bidi overrides)
	findings = append(findings, detectScriptObfuscation(doc)...)

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

// truncateEvidence returns s truncated to max runes with ellipsis when needed.
func truncateEvidence(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
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
