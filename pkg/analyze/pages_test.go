package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectPagesRisks(t *testing.T) {
	tests := []struct {
		name     string
		doc      *pipeline.Document
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "pages_job_with_mr_trigger",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "pages",
					Stage: "deploy",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/"},
					},
					Rules: []any{
						map[string]any{"if": `$CI_MERGE_REQUEST_IID`},
					},
				}},
			},
			wantIDs: []string{PagesMRDeployRiskID},
		},
		{
			name: "pages_job_with_sensitive_paths",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "pages",
					Stage: "deploy",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/", "coverage/", "docs/api/"},
					},
				}},
			},
			wantIDs: []string{PagesSensitivePathID},
		},
		{
			name: "pages_job_public_deploy",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "pages",
					Stage: "deploy",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/"},
					},
				}},
			},
			wantIDs: []string{PagesPublicDeployID},
		},
		{
			name: "non_pages_job_no_findings",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Stage:  "build",
					Script: []string{"go build"},
				}},
			},
			wantNone: true,
		},
		{
			name:     "nil_doc_no_findings",
			doc:      nil,
			wantNone: true,
		},
		{
			name: "pages_stage_detected",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "deploy_docs",
					Stage: "pages",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/"},
					},
				}},
			},
			wantIDs: []string{PagesPublicDeployID},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPagesRisks(tt.doc)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(got), got)
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
