package analyze

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const ArtifactReportInjectionID = "ARTIFACT_REPORT_INJECTION"

var knownScanners = []string{
	"gitleaks", "trufflehog", "semgrep", "bandit", "brakeman",
	"gosec", "trivy", "grype", "snyk", "sonar-scanner",
	"dependency-check", "retire", "npm audit", "yarn audit",
	"safety", "bundler-audit", "cargo-audit",
	"sast-analyzer", "secret-detection", "dependency-scanning",
	"container-scanning", "dast", "license-scanning",
	"gl-sast", "gl-secret", "gl-dependency", "gl-container",
}

func detectArtifactReportInjection(doc *pipeline.Document) []Finding {
	var findings []Finding

	for _, job := range doc.Jobs {
		if !jobHasSecurityReportArtifact(job, doc) {
			continue
		}

		scripts := effectiveScripts(job, doc)
		if scriptInvokesScanner(scripts) {
			continue
		}

		sev := SeverityMedium
		if jobTriggersOnMR(job.Rules) {
			sev = SeverityHigh
		}

		findings = append(findings, Finding{
			ID:       ArtifactReportInjectionID,
			Severity: sev,
			Title:    "Security report artifact without recognized scanner",
			Description: "Job '" + job.Name + "' produces security report artifacts but does not " +
				"invoke a recognized scanner. An attacker can inject clean reports to suppress real findings.",
			Evidence: stringutil.TruncateEvidence("Job: "+job.Name, 200),
			JobName:  job.Name,
		})
	}

	return findings
}

func jobHasSecurityReportArtifact(job pipeline.Job, doc *pipeline.Document) bool {
	rawJob, ok := doc.Raw[job.Name].(map[string]any)
	if !ok {
		return false
	}
	artifacts, ok := rawJob["artifacts"].(map[string]any)
	if !ok {
		return false
	}
	reports, ok := artifacts["reports"].(map[string]any)
	if !ok {
		return false
	}
	reportKeys := []string{"sast", "dast", "dependency_scanning", "secret_detection", "container_scanning", "sarif"}
	for _, k := range reportKeys {
		if _, exists := reports[k]; exists {
			return true
		}
	}
	return false
}

func scriptInvokesScanner(scripts []string) bool {
	joined := strings.ToLower(strings.Join(scripts, "\n"))
	for _, scanner := range knownScanners {
		if strings.Contains(joined, scanner) {
			return true
		}
	}
	return false
}
