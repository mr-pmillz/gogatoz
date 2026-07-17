package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectVariableInheritanceRisk(t *testing.T) {
	tests := []struct {
		name        string
		doc         *pipeline.Document
		projectVars []VariableInfo
		groupVars   []VariableInfo
		wantIDs     []string
		wantNone    bool
	}{
		{
			name: "yaml_shadows_protected_project_var",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:      "build",
					Script:    []string{"echo $DB_PASSWORD"},
					Variables: map[string]any{"DB_PASSWORD": "hardcoded"},
				}},
			},
			projectVars: []VariableInfo{
				{Key: "DB_PASSWORD", Protected: true, Masked: true, Source: "project"},
			},
			wantIDs: []string{VarInheritanceShadowID},
		},
		{
			name: "unmasked_secret_pattern",
			doc:  &pipeline.Document{},
			projectVars: []VariableInfo{
				{Key: "API_TOKEN", Protected: true, Masked: false, Source: "project"},
			},
			wantIDs: []string{VarUnmaskedSecretID},
		},
		{
			name: "unprotected_masked_secret",
			doc:  &pipeline.Document{},
			projectVars: []VariableInfo{
				{Key: "DEPLOY_KEY", Protected: false, Masked: true, Source: "project"},
			},
			wantIDs: []string{VarUnprotectedSecretID},
		},
		{
			name: "mr_override_risk",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "deploy",
					Script: []string{"curl -H \"Authorization: $API_KEY\" https://api.example.com"},
					Rules:  []any{map[string]any{"if": "$CI_MERGE_REQUEST_IID"}},
				}},
			},
			projectVars: []VariableInfo{
				{Key: "API_KEY", Protected: false, Masked: true, Source: "project"},
			},
			wantIDs: []string{VarMROverrideRiskID},
		},
		{
			name: "properly_protected_and_masked",
			doc:  &pipeline.Document{},
			projectVars: []VariableInfo{
				{Key: "SAFE_TOKEN", Protected: true, Masked: true, Source: "project"},
			},
			wantNone: true,
		},
		{
			name:     "nil_doc_no_vars",
			doc:      nil,
			wantNone: true,
		},
		{
			name:     "no_vars",
			doc:      &pipeline.Document{},
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectVariableInheritanceRisk(tt.doc, tt.projectVars, tt.groupVars)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(got), findingIDs(got))
				}
				return
			}
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range got {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s, got %v", wantID, findingIDs(got))
				}
			}
		})
	}
}
