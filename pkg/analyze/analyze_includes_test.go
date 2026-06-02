package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestIncludeRisks_RemoteAndUnpinnedProject(t *testing.T) {
	doc := &pipeline.Document{
		Includes: []pipeline.Include{
			{Type: pipeline.IncludeRemote, Remote: "https://example.com/ci.yml"},
			{Type: pipeline.IncludeProject, Project: "group/proj", File: []string{"ci.yml"}}, // no ref -> unpinned
		},
	}
	findings, err := Run(doc)
	if err != nil {
		// analyzer returns nil error unless partial; treat any error as failure for this unit test
		t.Fatalf("Run returned error: %v", err)
	}
	var haveRemote, haveUnpinned bool
	for _, f := range findings {
		if f.ID == "INCLUDE_REMOTE" {
			haveRemote = true
		}
		if f.ID == "INCLUDE_PROJECT_UNPINNED" {
			haveUnpinned = true
		}
	}
	if !haveRemote {
		t.Fatalf("expected INCLUDE_REMOTE finding, got: %+v", findings)
	}
	if !haveUnpinned {
		t.Fatalf("expected INCLUDE_PROJECT_UNPINNED finding, got: %+v", findings)
	}
}
