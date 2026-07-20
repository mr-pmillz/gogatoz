package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

// detectLOTPToolExec flags MR-triggered jobs that invoke Living-off-the-Pipeline (LOTP)
// tools. These tools read configuration from the repository, so an attacker who submits
// an MR with a weaponized config file (e.g., Makefile, package.json, .eslintrc) can
// achieve arbitrary code execution when the pipeline runs.
//
// Severity: HIGH when self-hosted runners are targeted; MEDIUM otherwise.
// Downgraded one level when fork protection is detected.
func detectLOTPToolExec(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		broadly := jobRulesAllowBroad(job.Rules)
		if !mrTriggered && !broadly {
			continue
		}

		hits := DetectLOTPTools(effectiveScripts(job, doc))
		if len(hits) == 0 {
			continue
		}

		hasForkProtection := checkForkProtection(job.Rules)
		hasSelfHosted := len(job.Tags) > 0

		sev := SeverityMedium
		if hasSelfHosted {
			sev = SeverityHigh
		}
		if hasForkProtection && sev == SeverityHigh {
			sev = SeverityMedium
		} else if hasForkProtection && sev == SeverityMedium {
			sev = SeverityLow
		}

		// Build evidence from first hit
		tool := hits[0]
		evid := fmt.Sprintf("tool=%s vector=%s config_files=%s tags=%v",
			tool.Name, tool.Vector, strings.Join(tool.ConfigFiles, ","), job.Tags)

		findings = append(findings, Finding{
			ID:          "LOTP_TOOL_EXEC",
			Severity:    sev,
			Title:       "LOTP tool in MR-triggered job enables config-file RCE",
			Description: fmt.Sprintf("Job runs %q, a Living-off-the-Pipeline tool that reads configuration from repository files (%s). An attacker can submit an MR that weaponizes these config files to execute arbitrary code. See: https://boostsecurityio.github.io/lotp/", tool.Name, strings.Join(tool.ConfigFiles, ", ")),
			Evidence:    stringutil.TruncateEvidence(evid, 200),
			JobName:     job.Name,
		})
	}
	return findings
}

// detectCacheKeyInjection flags jobs whose cache key is derived from an
// attacker-controllable CI variable. An attacker can manipulate the cache key to
// target a specific cache entry, enabling cache poisoning across pipelines.
func detectCacheKeyInjection(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		if job.Cache == nil {
			continue
		}
		keyStr := extractCacheKeyString(job.Cache)
		if keyStr == "" {
			continue
		}
		vars := extractCIVariables(keyStr)
		var unsafeVars []string
		for _, v := range vars {
			if isUnsafeVariable(v) {
				unsafeVars = append(unsafeVars, v)
			}
		}
		if len(unsafeVars) == 0 {
			continue
		}

		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		sev := SeverityMedium
		if mrTriggered {
			sev = SeverityHigh
		}

		findings = append(findings, Finding{
			ID:       "CACHE_KEY_INJECTION",
			Severity: sev,
			Title:    "Cache key uses attacker-controllable CI variable",
			Description: "Cache key is derived from an attacker-controllable variable. An attacker can craft an MR to target a specific cache entry, injecting malicious content that affects other pipelines." +
				" Affected variables: " + strings.Join(unsafeVars, ", "),
			Evidence: stringutil.TruncateEvidence(fmt.Sprintf("cache_key=%s vars=%v", keyStr, unsafeVars), 200),
			JobName:  job.Name,
		})
	}
	return findings
}

// detectOIDCTokenMRRisk flags MR-triggered jobs that define id_tokens. GitLab issues
// OIDC tokens usable against cloud providers (AWS, GCP, Azure). A fork author who
// triggers such a job can capture and use these tokens.
func detectOIDCTokenMRRisk(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		if !jobHasIDTokens(doc, job.Name) {
			continue
		}
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		broadly := jobRulesAllowBroad(job.Rules)
		if mrTriggered {
			findings = append(findings, Finding{
				ID:          "OIDC_TOKEN_MR_RISK",
				Severity:    SeverityHigh,
				Title:       "OIDC token issued in MR-triggered job",
				Description: "Job defines id_tokens and is triggered by merge request events. GitLab will issue a signed OIDC token to this job. Fork authors can trigger this job and capture the token to authenticate against cloud providers (AWS, GCP, Azure Workload Identity, etc.).",
				Evidence:    stringutil.TruncateEvidence("job="+job.Name+" has id_tokens", 200),
				JobName:     job.Name,
			})
		} else if broadly || job.Rules == nil {
			findings = append(findings, Finding{
				ID:          "OIDC_TOKEN_MR_RISK",
				Severity:    SeverityMedium,
				Title:       "OIDC token issued in broadly-triggered job",
				Description: "Job defines id_tokens and runs on push events or has broad trigger rules. Anyone with push access can forge valid OIDC provenance by pushing a commit, even without merge request review. Valid provenance from a compromised commit was the AsyncAPI attack pattern.",
				Evidence:    stringutil.TruncateEvidence("job="+job.Name+" has id_tokens, trigger=push/broad", 200),
				JobName:     job.Name,
			})
		}
	}
	return findings
}

const OIDCProvenanceAnomalyID = "OIDC_PROVENANCE_ANOMALY"

// detectOIDCProvenanceAnomaly flags push/broad-triggered jobs with OIDC tokens
// where branch protection is absent. Unlike OIDC_TOKEN_MR_RISK (MR path), this
// detects the push-triggered OIDC path where anyone with push access can forge
// valid provenance without code review.
func detectOIDCProvenanceAnomaly(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		if !jobHasIDTokens(doc, job.Name) {
			continue
		}
		if jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only) {
			continue
		}
		hasForkProtection := false
		if job.Rules != nil {
			text := strings.ToLower(toJSONString(job.Rules))
			hasForkProtection = strings.Contains(text, "ci_commit_ref_protected") ||
				strings.Contains(text, "ci_project_namespace") ||
				strings.Contains(text, "protected")
		}
		if hasForkProtection {
			continue
		}
		sev := SeverityMedium
		desc := "Job defines id_tokens and runs on push/broad triggers without branch protection rules. " +
			"Anyone with push access can forge valid OIDC provenance by pushing a commit. " +
			"This is the AsyncAPI attack pattern — valid cloud credentials from an unreviewed commit."
		if job.Rules == nil {
			sev = SeverityHigh
			desc += " No rules defined — job runs on all pipeline sources."
		}
		findings = append(findings, Finding{
			ID:          OIDCProvenanceAnomalyID,
			Severity:    sev,
			Title:       "OIDC provenance forgeable without branch protection",
			Description: desc,
			Evidence:    stringutil.TruncateEvidence("job="+job.Name+" has id_tokens, no protected branch gate", 200),
			JobName:     job.Name,
		})
	}
	return findings
}

// detectTriggerChainRisk flags MR-triggered jobs that launch downstream pipelines
// via trigger:. Fork authors can use this to trigger cross-project pipelines, and
// with strategy:depend the parent waits for the downstream — exposing timing and
// context to the attacker.
func detectTriggerChainRisk(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		if job.Trigger == nil {
			continue
		}
		mrTriggered := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		broadly := jobRulesAllowBroad(job.Rules)
		if !mrTriggered && !broadly {
			continue
		}

		strategy, _ := job.Trigger["strategy"].(string)
		sev := SeverityMedium
		desc := "MR-triggered job launches a downstream pipeline via trigger:. Fork authors can trigger cross-project pipelines, potentially accessing downstream secrets or resources."
		if strings.EqualFold(strategy, "depend") {
			sev = SeverityHigh
			desc += " With strategy:depend the parent waits for the downstream, exposing timing-based attacks."
		}

		evid := fmt.Sprintf("trigger=%v strategy=%s", job.Trigger, strategy)
		f := Finding{
			ID:          "TRIGGER_CHAIN_RISK",
			Severity:    sev,
			Title:       "Downstream trigger in MR-triggered job",
			Description: desc,
			Evidence:    stringutil.TruncateEvidence(evid, 200),
			JobName:     job.Name,
		}
		if proj, ok := job.Trigger["project"].(string); ok && proj != "" {
			f.Deps = []Dependency{{Kind: "trigger", Path: proj}}
		}
		findings = append(findings, f)
	}
	return findings
}

// --- helpers ---

// extractCacheKeyString returns the cache key as a string. Handles both direct string
// keys and the structured form (key: {files: [...], prefix: "$VAR"}).
func extractCacheKeyString(cache map[string]any) string {
	if cache == nil {
		return ""
	}
	switch k := cache["key"].(type) {
	case string:
		return k
	case map[string]any:
		if prefix, ok := k["prefix"].(string); ok {
			return prefix
		}
	}
	return ""
}

// jobHasIDTokens returns true when the raw YAML for the given job name contains an
// id_tokens: block. This field is not modeled in the Job struct so we reach into doc.Raw.
func jobHasIDTokens(doc *pipeline.Document, jobName string) bool {
	if doc == nil || doc.Raw == nil {
		return false
	}
	rawJob, ok := doc.Raw[jobName].(map[string]any)
	if !ok {
		return false
	}
	_, has := rawJob["id_tokens"]
	return has
}
