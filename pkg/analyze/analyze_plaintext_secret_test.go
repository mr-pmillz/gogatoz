package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// findingEvidence returns the Evidence of the first finding with the given ID.
func findingEvidence(fs []Finding, id string) (string, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f.Evidence, true
		}
	}
	return "", false
}

// secretDoc builds a document with a secret-like global variable and a
// secret-like job variable, both of which trigger looksLikeSecretKey.
func secretDoc() *pipeline.Document {
	return &pipeline.Document{
		Variables: map[string]any{"MY_TOKEN": "glpat-AAAAAAAAAAAAAAAAAAAA"},
		Jobs: []pipeline.Job{{
			Name:      "deploy",
			Variables: map[string]any{"JOB_SECRET": "p@ssw0rd-value-123"},
		}},
	}
}

func TestPlaintextSecret_UnredactedByDefault(t *testing.T) {
	findings, err := Run(secretDoc())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got, ok := findingEvidence(findings, "PLAINTEXT_SECRET")
	if !ok {
		t.Fatalf("expected PLAINTEXT_SECRET finding, got: %+v", findings)
	}
	if want := "MY_TOKEN=glpat-AAAAAAAAAAAAAAAAAAAA"; got != want {
		t.Errorf("global evidence: got %q, want %q", got, want)
	}

	gotJob, ok := findingEvidence(findings, "PLAINTEXT_SECRET_JOB")
	if !ok {
		t.Fatalf("expected PLAINTEXT_SECRET_JOB finding, got: %+v", findings)
	}
	if want := "JOB_SECRET=p@ssw0rd-value-123 (job=deploy)"; gotJob != want {
		t.Errorf("job evidence: got %q, want %q", gotJob, want)
	}
}

func TestPlaintextSecret_RedactedWithOption(t *testing.T) {
	findings, err := Run(secretDoc(), WithRedactedSecrets())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got, ok := findingEvidence(findings, "PLAINTEXT_SECRET")
	if !ok {
		t.Fatalf("expected PLAINTEXT_SECRET finding, got: %+v", findings)
	}
	if want := "MY_TOKEN=<redacted>"; got != want {
		t.Errorf("global evidence: got %q, want %q", got, want)
	}

	gotJob, ok := findingEvidence(findings, "PLAINTEXT_SECRET_JOB")
	if !ok {
		t.Fatalf("expected PLAINTEXT_SECRET_JOB finding, got: %+v", findings)
	}
	if want := "JOB_SECRET=<redacted> (job=deploy)"; gotJob != want {
		t.Errorf("job evidence: got %q, want %q", gotJob, want)
	}
}
