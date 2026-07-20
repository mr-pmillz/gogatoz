package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectSBOMIssues(t *testing.T) {
	tests := []struct {
		name     string
		doc      *pipeline.Document
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "image_with_latest_tag",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "node:latest",
					Script: []string{"npm test"},
				}},
			},
			wantIDs: []string{SBOMUnpinnedImageID},
		},
		{
			name: "image_with_no_tag",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "python",
					Script: []string{"pytest"},
				}},
			},
			wantIDs: []string{SBOMUnpinnedImageID},
		},
		{
			name: "image_pinned_with_digest",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "alpine@sha256:abc123def456",
					Script: []string{"echo ok"},
				}},
			},
			wantNone: true,
		},
		{
			name: "image_with_version_no_digest",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "node:18.20",
					Script: []string{"npm test"},
				}},
			},
			wantIDs: []string{SBOMNoDigestID},
		},
		{
			name:     "nil_doc",
			doc:      nil,
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSBOMIssues(tt.doc)
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
