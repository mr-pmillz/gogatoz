package analyze

import (
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectEnvironmentRisks(t *testing.T) {
	now := time.Now()
	stale := now.Add(-100 * 24 * time.Hour) // 100 days ago

	tests := []struct {
		name     string
		doc      *pipeline.Document
		envs     []EnvironmentInfo
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "unprotected_production_deploy",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:        "deploy",
					Environment: "production",
					Script:      []string{"deploy.sh"},
				}},
			},
			envs: []EnvironmentInfo{
				{Name: "production", Tier: "production", RequiredApprovalCount: 0},
			},
			wantIDs: []string{EnvUnprotectedDeployID, EnvNoApprovalGateID},
		},
		{
			name: "mr_triggered_deploy",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:        "deploy",
					Environment: "staging",
					Script:      []string{"deploy.sh"},
					Rules:       []any{map[string]any{"if": "$CI_MERGE_REQUEST_IID"}},
				}},
			},
			envs: []EnvironmentInfo{
				{Name: "staging", Tier: "staging"},
			},
			wantIDs: []string{EnvMRDeployRiskID},
		},
		{
			name: "stale_environment",
			doc:  &pipeline.Document{},
			envs: []EnvironmentInfo{
				{Name: "old-staging", Tier: "staging", State: "available", LastDeployedAt: &stale},
			},
			wantIDs: []string{EnvStaleDeploymentID},
		},
		{
			name:    "nil_doc",
			doc:     nil,
			envs:    []EnvironmentInfo{{Name: "prod"}},
			wantIDs: []string{},
		},
		{
			name:     "no_envs",
			doc:      &pipeline.Document{},
			wantNone: true,
		},
		{
			name: "protected_environment_no_finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:        "deploy",
					Environment: "production",
					Script:      []string{"deploy.sh"},
				}},
			},
			envs: []EnvironmentInfo{
				{Name: "production", Tier: "production", RequiredApprovalCount: 2, ProtectedBranches: []string{"main"}},
			},
			// No ENV_UNPROTECTED_DEPLOY because it has approvals and protected branches
			// Still gets ENV_NO_APPROVAL_GATE? No, RequiredApprovalCount is 2
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectEnvironmentRisks(tt.doc, tt.envs)
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
