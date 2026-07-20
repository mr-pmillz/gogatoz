package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	VarInheritanceShadowID = "VAR_INHERITANCE_SHADOW"
	VarUnmaskedSecretID    = "VAR_UNMASKED_SECRET"    //nolint:gosec // finding ID, not a credential
	VarUnprotectedSecretID = "VAR_UNPROTECTED_SECRET" //nolint:gosec // finding ID, not a credential
	VarMROverrideRiskID    = "VAR_MR_OVERRIDE_RISK"
)

// VariableInfo captures metadata about a CI/CD variable fetched from the GitLab API.
// Defined in the analyze package to avoid circular imports (enumerate imports analyze).
type VariableInfo struct {
	Key              string `json:"key"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	EnvironmentScope string `json:"environment_scope"`
	Source           string `json:"source"` // "project" or "group"
}

// VariableData bundles project and group variable metadata for analysis.
type VariableData struct {
	ProjectVars []VariableInfo
	GroupVars   []VariableInfo
}

var secretKeyPatterns = []string{
	"TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL", "APIKEY",
	"API_KEY", "PRIVATE", "AUTH", "PASSPHRASE",
}

func looksLikeSecretVar(key string) bool {
	upper := strings.ToUpper(key)
	for _, pat := range secretKeyPatterns {
		if strings.Contains(upper, pat) {
			return true
		}
	}
	return false
}

// checkVarMetadata inspects API-level variable attributes for missing masking or protection.
func checkVarMetadata(allVars []VariableInfo) []Finding {
	var findings []Finding
	for _, v := range allVars {
		if looksLikeSecretVar(v.Key) && !v.Masked {
			findings = append(findings, Finding{
				ID:          VarUnmaskedSecretID,
				Severity:    SeverityHigh,
				Title:       "CI/CD variable with secret-like name is not masked",
				Description: "A project or group CI/CD variable whose name suggests it holds a secret is not configured with masked=true. The value will be visible in job logs.",
				Evidence:    fmt.Sprintf("key=%s source=%s masked=false", v.Key, v.Source),
			})
		}
		if v.Masked && !v.Protected {
			findings = append(findings, Finding{
				ID:          VarUnprotectedSecretID,
				Severity:    SeverityHigh,
				Title:       "Masked CI/CD variable is not protected",
				Description: "A masked variable is accessible from unprotected branches and MR pipelines. An attacker with MR access can exfiltrate the value via artifact-based or network-based methods.",
				Evidence:    fmt.Sprintf("key=%s source=%s masked=true protected=false", v.Key, v.Source),
			})
		}
	}
	return findings
}

// checkJobVarOverrides detects YAML-level variable shadowing and MR override risks.
func checkJobVarOverrides(doc *pipeline.Document, apiVarMap map[string]VariableInfo) []Finding {
	var findings []Finding
	for _, job := range doc.Jobs {
		for varKey := range job.Variables {
			if apiVar, ok := apiVarMap[varKey]; ok && apiVar.Protected {
				findings = append(findings, Finding{
					ID:          VarInheritanceShadowID,
					Severity:    SeverityMedium,
					Title:       "Job variable shadows a protected CI/CD variable",
					Description: "A job-level variable defined in .gitlab-ci.yml shadows a protected project or group variable. The YAML value takes precedence, bypassing the protected variable's security controls.",
					Evidence:    fmt.Sprintf("key=%s job=%s shadows %s-level protected variable", varKey, job.Name, apiVar.Source),
					JobName:     job.Name,
				})
			}
		}
		if !jobHasMRTrigger(job) {
			continue
		}
		findings = append(findings, checkMROverrideRisk(job, doc, apiVarMap)...)
	}
	return findings
}

// checkMROverrideRisk checks whether an MR-triggered job references unprotected variables in scripts.
func checkMROverrideRisk(job pipeline.Job, doc *pipeline.Document, apiVarMap map[string]VariableInfo) []Finding {
	var findings []Finding
	for _, line := range effectiveScripts(job, doc) {
		for varKey, apiVar := range apiVarMap {
			if apiVar.Protected {
				continue
			}
			ref := "$" + varKey
			refBraced := "${" + varKey + "}"
			if strings.Contains(line, ref) || strings.Contains(line, refBraced) {
				findings = append(findings, Finding{
					ID:          VarMROverrideRiskID,
					Severity:    SeverityMedium,
					Title:       "MR pipeline can override unprotected variable used in script",
					Description: "A CI/CD variable referenced in a script is not protected. An MR pipeline can override it with a malicious value, potentially injecting commands or altering behavior.",
					Evidence:    fmt.Sprintf("key=%s job=%s source=%s used in script", varKey, job.Name, apiVar.Source),
					JobName:     job.Name,
				})
				break
			}
		}
	}
	return findings
}

func detectVariableInheritanceRisk(doc *pipeline.Document, projectVars, groupVars []VariableInfo) []Finding {
	allAPIVars := append(projectVars, groupVars...) //nolint:gocritic // intentional append to new slice
	if len(allAPIVars) == 0 {
		return nil
	}

	findings := checkVarMetadata(allAPIVars)

	if doc == nil {
		return findings
	}

	apiVarMap := map[string]VariableInfo{}
	for _, v := range allAPIVars {
		apiVarMap[v.Key] = v
	}

	findings = append(findings, checkJobVarOverrides(doc, apiVarMap)...)
	return findings
}
