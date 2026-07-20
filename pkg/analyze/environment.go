package analyze

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	EnvUnprotectedDeployID = "ENV_UNPROTECTED_DEPLOY"
	EnvNoApprovalGateID    = "ENV_NO_APPROVAL_GATE"
	EnvMRDeployRiskID      = "ENV_MR_DEPLOY_RISK"
	EnvStaleDeploymentID   = "ENV_STALE_DEPLOYMENT"
)

// EnvironmentInfo captures metadata about a GitLab environment fetched from the API.
type EnvironmentInfo struct {
	ID                    int64      `json:"id"`
	Name                  string     `json:"name"`
	Tier                  string     `json:"tier"`
	ExternalURL           string     `json:"external_url,omitempty"`
	State                 string     `json:"state"`
	RequiredApprovalCount int        `json:"required_approval_count"`
	ProtectedBranches     []string   `json:"protected_branches,omitempty"`
	LastDeployedAt        *time.Time `json:"last_deployed_at,omitempty"`
}

const staleDays = 90

func detectEnvironmentRisks(doc *pipeline.Document, envs []EnvironmentInfo) []Finding {
	if len(envs) == 0 {
		return nil
	}

	var findings []Finding
	envMap := map[string]EnvironmentInfo{}
	for _, e := range envs {
		envMap[strings.ToLower(e.Name)] = e
	}

	// Environment-level checks (no doc required)
	for _, e := range envs {
		isProd := strings.EqualFold(e.Tier, "production")
		if isProd && e.RequiredApprovalCount == 0 {
			findings = append(findings, Finding{
				ID:          EnvNoApprovalGateID,
				Severity:    SeverityMedium,
				Title:       "Production environment lacks required approvals",
				Description: "A production-tier environment has no required approval count. Any pipeline reaching the deployment stage can deploy without human review.",
				Evidence:    fmt.Sprintf("environment=%s tier=%s approvals=0", e.Name, e.Tier),
			})
		}

		if e.State == "available" && e.LastDeployedAt != nil {
			daysSince := int(time.Since(*e.LastDeployedAt).Hours() / 24)
			if daysSince > staleDays {
				findings = append(findings, Finding{
					ID:          EnvStaleDeploymentID,
					Severity:    SeverityLow,
					Title:       "Stale environment with no recent deployments",
					Description: "An active environment has not had a deployment in over 90 days. This may represent an abandoned attack surface with outdated code.",
					Evidence:    fmt.Sprintf("environment=%s last_deploy=%dd_ago state=%s", e.Name, daysSince, e.State),
				})
			}
		}
	}

	if doc == nil {
		return findings
	}

	// Job-level checks requiring the parsed document
	for _, job := range doc.Jobs {
		if job.Environment == "" {
			continue
		}
		envName := strings.ToLower(job.Environment)
		env, exists := envMap[envName]

		if exists && len(env.ProtectedBranches) == 0 && env.RequiredApprovalCount == 0 {
			findings = append(findings, Finding{
				ID:          EnvUnprotectedDeployID,
				Severity:    SeverityHigh,
				Title:       "Job deploys to unprotected environment",
				Description: "A CI job deploys to an environment that has no protection rules (no branch restrictions, no approval requirements).",
				Evidence:    fmt.Sprintf("job=%s environment=%s tier=%s", job.Name, env.Name, env.Tier),
				JobName:     job.Name,
			})
		}

		if jobHasMRTrigger(job) {
			findings = append(findings, Finding{
				ID:          EnvMRDeployRiskID,
				Severity:    SeverityHigh,
				Title:       "MR-triggered job deploys to environment",
				Description: "A job that runs on merge request pipelines deploys to an environment. An attacker can trigger deployments via MR without proper authorization.",
				Evidence:    fmt.Sprintf("job=%s environment=%s has_mr_trigger=true", job.Name, job.Environment),
				JobName:     job.Name,
			})
		}
	}

	return findings
}
