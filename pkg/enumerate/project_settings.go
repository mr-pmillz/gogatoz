package enumerate

import (
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	JobTokenPushEnabledID       = "JOB_TOKEN_PUSH_ENABLED" //nolint:gosec // finding ID, not a credential
	ForkPipelineParentEnabledID = "FORK_PIPELINE_PARENT_ENABLED"
	PublicPipelineJobsID        = "PUBLIC_PIPELINE_JOBS"
)

// projectSettingFindings reports risky project settings that are exposed by
// the GitLab Projects API. It intentionally checks only enabled values because
// older GitLab versions may omit newer boolean fields from the response.
func projectSettingFindings(project *gitlab.Project) []analyze.Finding {
	if project == nil {
		return nil
	}
	var findings []analyze.Finding
	if project.CIPushRepositoryForJobTokenAllowed {
		findings = append(findings, analyze.Finding{
			ID:       JobTokenPushEnabledID,
			Severity: analyze.SeverityHigh,
			Title:    "CI job tokens can push to the repository",
			Description: "Jobs in this project can use CI_JOB_TOKEN to push repository changes. " +
				"A compromised pipeline can modify source or CI configuration using the identity that triggered the job.",
			Evidence:       "ci_push_repository_for_job_token_allowed=true",
			Recommendation: "Disable job-token repository pushes unless required, restrict the job-token allowlist, and protect CI configuration paths.",
		})
	}
	if project.CIAllowForkPipelinesToRunInParentProject {
		findings = append(findings, analyze.Finding{
			ID:       ForkPipelineParentEnabledID,
			Severity: analyze.SeverityHigh,
			Title:    "Fork pipelines can run in the parent project",
			Description: "Fork merge request pipelines may run in the parent project context, " +
				"where trusted runners and protected resources can be exposed to attacker-controlled changes.",
			Evidence:       "ci_allow_fork_pipelines_to_run_in_parent_project=true",
			Recommendation: "Disable parent-project execution for fork pipelines or require trusted review before running them.",
		})
	}
	if project.PublicJobs && project.Visibility != gitlab.PublicVisibility {
		findings = append(findings, analyze.Finding{
			ID:       PublicPipelineJobsID,
			Severity: analyze.SeverityMedium,
			Title:    "Pipeline jobs are public on a non-public project",
			Description: "Job details and logs can be visible more broadly than the project, " +
				"which can expose internal paths, build metadata, and accidentally logged credentials.",
			Evidence:       fmt.Sprintf("public_jobs=true project_visibility=%s", project.Visibility),
			Recommendation: "Disable public jobs for non-public projects and rotate credentials exposed in historical logs.",
		})
	}
	return findings
}
