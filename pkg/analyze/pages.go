package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	PagesPublicDeployID  = "PAGES_PUBLIC_DEPLOY"
	PagesMRDeployRiskID  = "PAGES_MR_DEPLOY_RISK"
	PagesSensitivePathID = "PAGES_SENSITIVE_PATH"
)

var pagesSensitivePatterns = []string{
	"coverage/", "docs/api/", "docs/internal/", "storybook/",
	".env", "config/", "swagger/", "openapi/",
}

func isPagesJob(job pipeline.Job) bool {
	if strings.EqualFold(job.Name, "pages") {
		return true
	}
	if strings.EqualFold(job.Stage, "pages") {
		return true
	}
	paths := artifactPaths(job)
	for _, p := range paths {
		if strings.HasPrefix(p, "public/") || p == "public" {
			if strings.EqualFold(job.Stage, "deploy") || strings.EqualFold(job.Name, "pages") {
				return true
			}
		}
	}
	return false
}

func artifactPaths(job pipeline.Job) []string {
	if job.Artifacts == nil {
		return nil
	}
	raw, ok := job.Artifacts["paths"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	var paths []string
	for _, v := range list {
		if s, ok := v.(string); ok {
			paths = append(paths, s)
		}
	}
	return paths
}

func detectPagesRisks(doc *pipeline.Document) []Finding {
	if doc == nil {
		return nil
	}
	var findings []Finding
	for _, job := range doc.Jobs {
		if !isPagesJob(job) {
			continue
		}

		if jobHasMRTrigger(job) {
			findings = append(findings, Finding{
				ID:          PagesMRDeployRiskID,
				Severity:    SeverityHigh,
				Title:       "Pages job can be triggered from MR pipelines",
				Description: "A GitLab Pages job runs on merge request pipelines, allowing content injection via MR. An attacker can deploy arbitrary content to the project's Pages URL.",
				Evidence:    fmt.Sprintf("job=%s has MR trigger rules", job.Name),
				JobName:     job.Name,
			})
		}

		paths := artifactPaths(job)
		var matched []string
		for _, p := range paths {
			for _, pat := range pagesSensitivePatterns {
				if strings.Contains(strings.ToLower(p), pat) {
					matched = append(matched, p)
					break
				}
			}
		}
		if len(matched) > 0 {
			findings = append(findings, Finding{
				ID:          PagesSensitivePathID,
				Severity:    SeverityMedium,
				Title:       "Pages artifacts include potentially sensitive paths",
				Description: "Pages deployment includes paths that commonly contain sensitive information such as coverage reports, API documentation, or configuration files.",
				Evidence:    fmt.Sprintf("job=%s sensitive_paths=%s", job.Name, strings.Join(matched, ", ")),
				JobName:     job.Name,
			})
		}

		findings = append(findings, Finding{
			ID:          PagesPublicDeployID,
			Severity:    SeverityMedium,
			Title:       "GitLab Pages deployment detected",
			Description: "A Pages job deploys static content. Verify that published content is intended to be public and does not expose internal documentation, credentials, or sensitive data.",
			Evidence:    fmt.Sprintf("job=%s stage=%s", job.Name, job.Stage),
			JobName:     job.Name,
		})
	}
	return findings
}

func jobHasMRTrigger(job pipeline.Job) bool {
	rules, ok := job.Rules.([]any)
	if !ok {
		return false
	}
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		ifClause, _ := rm["if"].(string)
		lower := strings.ToLower(ifClause)
		if strings.Contains(lower, "ci_merge_request") || strings.Contains(lower, "merge_request_event") {
			return true
		}
	}
	return false
}
