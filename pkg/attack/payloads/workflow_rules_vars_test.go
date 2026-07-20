package payloads

import (
	"strings"
	"testing"
)

func TestGenerateWorkflowRulesVarsYAML(t *testing.T) {
	tests := []struct {
		name     string
		opts     WorkflowRulesVarsOptions
		contains []string
		absent   []string
	}{
		{
			name: "default workflow vars",
			opts: WorkflowRulesVarsOptions{},
			contains: []string{
				"workflow:",
				"rules:",
				"merge_request_event",
				"variables:",
				"NPM_CONFIG_REGISTRY:",
				"PIP_INDEX_URL:",
				"GOPROXY:",
				"when: always",
				"allow_failure: true",
			},
			absent: []string{
				"CI_REGISTRY:",
			},
		},
		{
			name: "custom variables",
			opts: WorkflowRulesVarsOptions{
				Variables: map[string]string{
					"DEPLOY_TOKEN": "attacker-token",
				},
				TriggerOn: "push",
			},
			contains: []string{
				`$CI_PIPELINE_SOURCE == "push"`,
				"DEPLOY_TOKEN:",
			},
			absent: []string{
				"NPM_CONFIG_REGISTRY:",
			},
		},
		{
			name: "with CI overrides",
			opts: WorkflowRulesVarsOptions{
				OverrideCI: true,
			},
			contains: []string{
				"CI_REGISTRY:",
				"CI_REGISTRY_IMAGE:",
				"registry.attacker.io",
			},
		},
		{
			name: "with tags",
			opts: WorkflowRulesVarsOptions{
				Common: CommonOptions{Tags: []string{"self-hosted"}},
			},
			contains: []string{
				"tags:",
				"self-hosted",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := GenerateWorkflowRulesVarsYAML(tc.opts)
			for _, s := range tc.contains {
				if !strings.Contains(y, s) {
					t.Errorf("expected %q in output:\n%s", s, y)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(y, s) {
					t.Errorf("unexpected %q in output:\n%s", s, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
