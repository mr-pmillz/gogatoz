package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestArtifacts_NoExpire_Finding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:      "build",
			Artifacts: map[string]any{"paths": []any{"out/*"}},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, "ARTIFACTS_NO_EXPIRE") {
		t.Fatalf("expected ARTIFACTS_NO_EXPIRE finding, got: %+v", findings)
	}
}

func TestArtifacts_WithExpire_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:      "build",
			Artifacts: map[string]any{"paths": []any{"out/*"}, "expire_in": "1 week"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, "ARTIFACTS_NO_EXPIRE") {
		t.Fatalf("did not expect ARTIFACTS_NO_EXPIRE finding, got: %+v", findings)
	}
}
