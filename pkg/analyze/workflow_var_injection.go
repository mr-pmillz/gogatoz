package analyze

import (
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const WorkflowVarInjectionID = "WORKFLOW_VAR_INJECTION"

var sensitiveWorkflowVarKeys = []string{
	"NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL",
	"GOPROXY", "GONOSUMDB", "GONOSUMCHECK",
	"DOCKER_AUTH_CONFIG", "DOCKER_CONFIG",
	"CI_REGISTRY", "CI_REGISTRY_IMAGE",
	"GRADLE_OPTS", "MAVEN_OPTS",
	"GEM_HOST_API_KEY", "BUNDLE_RUBYGEMS__ORG",
	"CARGO_REGISTRIES_CRATES_IO_INDEX",
}

func detectWorkflowVarInjection(doc *pipeline.Document) []Finding {
	var findings []Finding

	rawWorkflow, ok := doc.Raw["workflow"].(map[string]any)
	if !ok {
		return nil
	}
	rawRules, ok := rawWorkflow["rules"].([]any)
	if !ok {
		return nil
	}

	for _, rule := range rawRules {
		ruleMap, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		vars, ok := ruleMap["variables"].(map[string]any)
		if !ok {
			continue
		}

		for varKey := range vars {
			if isSensitiveWorkflowVar(varKey) {
				findings = append(findings, Finding{
					ID:       WorkflowVarInjectionID,
					Severity: SeverityHigh,
					Title:    "Workflow-level variable injection of sensitive key",
					Description: "Workflow rules:variables overrides '" + varKey + "', a security-sensitive " +
						"variable that affects all downstream jobs. An attacker controlling this value " +
						"can redirect package registries, inject credentials, or hijack builds.",
					Evidence: stringutil.TruncateEvidence("workflow.rules.variables."+varKey, 200),
				})
			}
		}
	}

	return findings
}

func isSensitiveWorkflowVar(key string) bool {
	upper := strings.ToUpper(key)
	return slices.Contains(sensitiveWorkflowVarKeys, upper)
}
