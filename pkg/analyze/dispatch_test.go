package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectDispatchTOCTOU_ManualNeedsMR(t *testing.T) {
	doc := &pipeline.Document{
		Workflow: pipeline.Workflow{Rules: map[string]any{"when": "always"}},
		Jobs: []pipeline.Job{
			{Name: "build", Script: []string{"echo hi"}, Rules: map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"}},
			{Name: "release", When: "manual", Needs: []string{"build"}},
		},
	}
	fs, _ := Run(doc)
	if !hasFindingID(fs, "DISPATCH_TOCTOU_RISK") {
		t.Fatalf("expected DISPATCH_TOCTOU_RISK, got: %+v", fs)
	}
}

func TestDetectPwnRequestNuances_EnvMR(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "deploy", Environment: "prod", Rules: map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"}},
		},
	}
	fs, _ := Run(doc)
	if !hasFindingID(fs, "PWN_REQUEST_DEPLOYMENT") {
		t.Fatalf("expected PWN_REQUEST_DEPLOYMENT, got: %+v", fs)
	}
}

func TestDetectPrivilegedRunnerUse_DindMR(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "docker", Services: []string{"docker:24.0-dind"}, Rules: map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"}},
		},
	}
	fs, _ := Run(doc)
	if !hasFindingID(fs, "PRIVILEGED_RUNNER_RISK") {
		t.Fatalf("expected PRIVILEGED_RUNNER_RISK, got: %+v", fs)
	}
}
