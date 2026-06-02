package analyze

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
}

// Option configures Run behavior.
type Option func(*runConfig)

// WithRedactedSecrets masks plaintext secret values in finding evidence
// (PLAINTEXT_SECRET / PLAINTEXT_SECRET_JOB). The variable name is still shown.
// By default Run leaves these values unredacted.
func WithRedactedSecrets() Option {
	return func(c *runConfig) { c.redactSecrets = true }
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

	// 2b) Risky remote script execution in job scripts
	for _, job := range doc.Jobs {
		for _, line := range job.Script {
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

	// Attach basic recommendations
	findings = withRecommendations(findings)
	return findings, nil
}

// withRecommendations attaches a simple recommendation string based on Finding ID.
func withRecommendations(in []Finding) []Finding {
	for i := range in {
		if strings.TrimSpace(in[i].Recommendation) != "" {
			continue
		}
		switch in[i].ID {
		case IncludeRemoteID:
			in[i].Recommendation = "Avoid remote includes; prefer project includes pinned to a commit. If remote is necessary, allowlist hosts and pin exact versions. See: https://docs.gitlab.com/ee/ci/yaml/includes.html#includeremote"
		case "INCLUDE_PROJECT_UNPINNED":
			in[i].Recommendation = "Pin project includes to a tag or commit to prevent upstream changes from silently altering your pipeline. See: https://docs.gitlab.com/ee/ci/yaml/includes.html#syntax-for-include"
		case "INCLUDE_COMPONENT":
			in[i].Recommendation = "Use trusted components and pin explicit versions; review inputs for injection risks. See: https://docs.gitlab.com/ee/ci/components/"
		case "SELF_HOSTED_EXPOSED":
			in[i].Recommendation = "Tighten job rules/only conditions, restrict to protected branches, and limit access to sensitive runner tags. See: https://docs.gitlab.com/ee/user/project/protected_branches/ and https://docs.gitlab.com/runner/"
		case "MR_TAGGED_RUNNER":
			in[i].Recommendation = "Restrict MR-triggered jobs on tagged runners to protected branches or require approvals; disable fork MR pipelines if unsafe. See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html and https://docs.gitlab.com/ee/user/project/protected_branches/"
		case "RISKY_REMOTE_SCRIPT":
			in[i].Recommendation = "Avoid piping network content into shells; vendor scripts or pin by checksum/version before execution. See: https://docs.gitlab.com/ee/ci/yaml/"
		case "ARTIFACTS_NO_EXPIRE":
			in[i].Recommendation = "Set artifacts:expire_in to a bounded period and avoid exposing sensitive artifacts. See: https://docs.gitlab.com/ee/ci/yaml/#artifacts"
		case "PLAINTEXT_SECRET", "PLAINTEXT_SECRET_JOB":
			in[i].Recommendation = "Move secrets into masked/protected CI variables or a secrets manager; rotate any exposed credentials. See: https://docs.gitlab.com/ee/ci/variables/"
		case "FORK_MR_UNPROTECTED":
			in[i].Recommendation = "Enable fork MR protections (protected branches, approvals, or disable fork MR pipelines). See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html#enable-or-disable-pipelines-for-merge-requests and https://docs.gitlab.com/ee/user/project/protected_branches/"
		case "DISPATCH_TOCTOU_RISK":
			in[i].Recommendation = "Constrain manual/triggered jobs and verify upstream state before use. Consider approvals and environment protections. See: https://docs.gitlab.com/ee/ci/yaml/#whenmanual and https://docs.gitlab.com/ee/ci/yaml/#needs"
		case "PWN_REQUEST_DEPLOYMENT":
			in[i].Recommendation = "Protect deployments (protected environments, approvals) and restrict MR-triggered deploys. See: https://docs.gitlab.com/ee/ci/environments/protected_environments.html and https://docs.gitlab.com/ee/user/project/merge_requests/approvals/"
		case "PRIVILEGED_RUNNER_RISK":
			in[i].Recommendation = "Avoid docker-in-docker or privileged context on MR-triggered jobs; prefer rootless or buildkit alternatives and hardened runners. See: https://docs.gitlab.com/ee/ci/docker/using_docker_build.html#use-docker-in-docker-workflow-with-dind and https://docs.gitlab.com/runner/security/"
		case "RUNNER_EXECUTOR_RISK":
			in[i].Recommendation = "Use docker or kubernetes executors with non-privileged configuration; restrict shell executors to isolated hosts with protected branch triggers. See: https://docs.gitlab.com/runner/executors/"
		case "VARIABLE_INJECTION":
			in[i].Recommendation = "Sanitize or avoid attacker-controllable CI variables (e.g., CI_MERGE_REQUEST_TITLE, CI_COMMIT_MESSAGE) in scripts; use fixed values or validated inputs instead of interpolating user-supplied data. See: https://docs.gitlab.com/ee/ci/variables/ and https://docs.gitlab.com/ee/ci/yaml/script.html"
		case "FORK_SCRIPT_EXECUTION":
			in[i].Recommendation = "Avoid executing repo-local scripts in MR-triggered jobs from forks. Use inline scripts, pin script checksums, or add fork protection rules (source project == target project). See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html"
		case "AI_PROMPT_INJECTION":
			in[i].Recommendation = "Do not run AI code review tools on untrusted fork MR content. Isolate AI workflows to trusted branches, use read-only permissions, validate AI outputs before committing, and never pass MR descriptions or untrusted file content as prompts. See: https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation"
		case "ARTIFACT_POISONING_RISK":
			in[i].Recommendation = "Avoid consuming artifacts from MR-triggered jobs in privileged downstream stages; use dependencies keyword to limit artifact scope, require approvals for artifact-producing MR pipelines, or validate artifact integrity before use. See: https://docs.gitlab.com/ee/ci/yaml/#dependencies and https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html"
		case "WORKFLOW_BROAD_RULES":
			in[i].Recommendation = "Restrict top-level workflow rules to specific branches, tags, or pipeline sources rather than using 'when: always'; gate pipelines with protected branch or approval requirements. See: https://docs.gitlab.com/ee/ci/yaml/workflow.html" //nolint:gosec // G602: i bounded by range
		case "SCRIPT_INJECTION_RISK":
			in[i].Recommendation = "Avoid executing repo-local scripts in MR-triggered jobs; use inline script commands, pin script checksums, or move scripts to a trusted project include. Add fork protection rules to prevent untrusted modifications. See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html" //nolint:gosec // G602: i bounded by range
		case "SELF_MERGE_POSSIBLE":
			in[i].Recommendation = "Require at least 2 approvals for merge requests and enable 'Prevent approval by author' in project settings. Use CODEOWNERS to enforce reviews for CI config and scripts. See: https://docs.gitlab.com/ee/user/project/merge_requests/approvals/ and https://docs.gitlab.com/ee/user/project/codeowners/" //nolint:gosec // G602: i bounded by range
		case "CACHE_POISONING_RISK":
			in[i].Recommendation = "Set cache policy to 'pull' for MR-triggered jobs to prevent cache writes from untrusted pipelines. Use separate cache keys per branch or pipeline source. See: https://docs.gitlab.com/ee/ci/caching/#cache-policy" //nolint:gosec // G602: i bounded by range
		default:
			in[i].Recommendation = "Review and harden configuration; apply least privilege and restrict triggers/inputs." //nolint:gosec // G602: i bounded by range
		}
	}
	return in
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
