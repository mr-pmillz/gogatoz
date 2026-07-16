package analyze

import (
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	WorkflowSecretExfilID   = "WORKFLOW_SECRET_EXFIL"   //nolint:gosec // finding ID, not a credential
	WorkflowArtifactExfilID = "WORKFLOW_ARTIFACT_EXFIL" //nolint:gosec // finding ID, not a credential
)

var disguisedJobNames = []string{
	"copilot-setup", "security-scan", "format-results", "code-format",
	"lint-check", "diagnostics", "optimize", "sysdiag", "dep-audit",
	"quality-gate", "code-quality", "pre-commit", "post-build",
	"validate-config", "compliance-check", "artifact-publish",
}

var toJSONSecretsRe = regexp.MustCompile(`(?i)toJSON\s*\(\s*secrets\s*\)`)

func detectWorkflowSecretExfil(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		lines := effectiveScripts(job, doc)
		hasDump := jobHasSecretsDump(lines)
		if !hasDump {
			continue
		}

		disguised := isDisguisedJobName(job.Name)
		signals := scanExfilSignals(lines)
		artifactOnly := jobExfilsViaArtifactOnly(job, lines)
		pushOnly := jobTriggeredOnPushOnly(job)

		if disguised && artifactOnly {
			findings = append(findings, Finding{
				ID:       WorkflowArtifactExfilID,
				Severity: SeverityCritical,
				Title:    "Disguised job exfiltrates secrets via artifacts",
				Description: "This job has a plausible tooling name but dumps environment secrets to a file " +
					"and uploads it as a CI artifact. This is the artifact-only exfiltration pattern used by Hades " +
					"and similar campaigns — no HTTP callback needed.",
				Evidence: truncateEvidence("job="+job.Name+" dump="+signals.envDumpEvidence, 200),
				JobName:  job.Name,
			})
			continue
		}

		if disguised && signals.httpExfil {
			findings = append(findings, Finding{
				ID:       WorkflowSecretExfilID,
				Severity: SeverityCritical,
				Title:    "Disguised job exfiltrates secrets via HTTP",
				Description: "This job has a plausible tooling name but dumps environment secrets and sends them " +
					"to an external endpoint. Disguised exfiltration bypasses casual code review.",
				Evidence: truncateEvidence("job="+job.Name+" dump="+signals.envDumpEvidence+" exfil="+signals.httpEvidence, 200),
				JobName:  job.Name,
			})
			continue
		}

		if artifactOnly && !hasExpireIn(job) {
			findings = append(findings, Finding{
				ID:       WorkflowArtifactExfilID,
				Severity: SeverityHigh,
				Title:    "Secrets dumped to persistent artifact",
				Description: "This job dumps environment variables to a file uploaded as an artifact with no expiration. " +
					"Anyone with project access can download the artifact and extract secrets indefinitely.",
				Evidence: truncateEvidence("job="+job.Name+" dump="+signals.envDumpEvidence, 200),
				JobName:  job.Name,
			})
			continue
		}

		if pushOnly && !signals.httpExfil && !artifactOnly {
			findings = append(findings, Finding{
				ID:       WorkflowSecretExfilID,
				Severity: SeverityHigh,
				Title:    "Push-triggered job dumps secrets without review",
				Description: "This job triggers on push events (not merge requests) and dumps environment secrets. " +
					"Push-triggered jobs bypass code review, creating a no-review exfiltration window.",
				Evidence: truncateEvidence("job="+job.Name+" dump="+signals.envDumpEvidence, 200),
				JobName:  job.Name,
			})
		}
	}
	return findings
}

func isDisguisedJobName(name string) bool {
	lower := strings.ToLower(name)
	for _, d := range disguisedJobNames {
		if lower == d || strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

func jobHasSecretsDump(lines []string) bool {
	for _, line := range lines {
		lower := strings.ToLower(line)
		if toJSONSecretsRe.MatchString(line) {
			return true
		}
		for _, cmd := range envDumpCmds {
			if strings.Contains(lower, strings.ToLower(cmd)) {
				return true
			}
		}
	}
	return false
}

var secretsDumpToFileRe = regexp.MustCompile(`(?i)(?:toJSON\s*\(\s*secrets\s*\)|printenv|env\b|set\b|export\b|compgen\s+-v|/proc/self/environ).*>>?\s*(\S+)`)

func jobExfilsViaArtifactOnly(job pipeline.Job, lines []string) bool {
	if job.Artifacts == nil {
		return false
	}
	dumpFile := extractDumpFilename(lines)
	if dumpFile == "" {
		dumpFile = extractSecretsDumpFilename(lines)
	}
	if dumpFile == "" {
		return false
	}
	signals := scanExfilSignals(lines)
	if signals.httpExfil {
		return false
	}
	return jobArtifactContains(job, dumpFile)
}

func extractSecretsDumpFilename(lines []string) string {
	for _, line := range lines {
		if m := secretsDumpToFileRe.FindStringSubmatch(line); len(m) >= 2 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

func jobTriggeredOnPushOnly(job pipeline.Job) bool {
	if job.Rules == nil && job.Only == nil {
		return false
	}
	if jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only) {
		return false
	}
	if job.Rules != nil {
		text := strings.ToLower(toJSONString(job.Rules))
		return strings.Contains(text, "push") || strings.Contains(text, "\"always\"")
	}
	if job.Only != nil {
		return onlyIsBroad(job.Only)
	}
	return false
}

func hasExpireIn(job pipeline.Job) bool {
	if job.Artifacts == nil {
		return false
	}
	if v, ok := job.Artifacts["expire_in"]; ok {
		s, isStr := v.(string)
		if isStr && strings.ToLower(s) == "never" {
			return false
		}
		return isStr && s != ""
	}
	return false
}
