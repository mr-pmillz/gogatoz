package artifactverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyMatchesSLSAProvenanceExpectations(t *testing.T) {
	t.Parallel()

	commit := strings.Repeat("a", 40)
	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`)},
	})
	provenance := writeProvenanceFixture(t, `{
  "_type":"https://in-toto.io/Statement/v1",
  "predicate":{
    "buildDefinition":{
      "externalParameters":{"source":"https://gitlab.invalid/group/project","ref":"refs/tags/v1.2.3"},
      "resolvedDependencies":[{"uri":"git+https://gitlab.invalid/group/project.git","digest":{"gitCommit":"`+commit+`"}}]
    },
    "runDetails":{"metadata":{"invocationId":"https://gitlab.invalid/group/project/-/pipelines/987"}}
  }
}`)

	report, err := Verify(context.Background(), Options{
		Artifact: artifact, Provenance: provenance,
		ExpectedRepository: "https://gitlab.invalid/group/project",
		ExpectedCommit:     commit, ExpectedRef: "refs/tags/v1.2.3", ExpectedPipeline: "987",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Provenance == nil || report.Provenance.Commit != commit || report.Provenance.Ref != "refs/tags/v1.2.3" {
		t.Fatalf("provenance summary = %+v", report.Provenance)
	}
	if reportHasFinding(report, ProvenanceMismatchID) || reportHasFinding(report, ReleaseTagMismatchID) {
		t.Fatalf("unexpected provenance finding: %+v", report.Findings)
	}
}

func TestVerifyReportsProvenanceAndReleaseTagMismatch(t *testing.T) {
	t.Parallel()

	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`)},
	})
	provenance := writeProvenanceFixture(t, `{
  "predicate":{"buildDefinition":{"externalParameters":{
    "source":"https://gitlab.invalid/other/project","ref":"refs/tags/v9.9.9"
  }}}
}`)

	report, err := Verify(context.Background(), Options{
		Artifact: artifact, Provenance: provenance,
		ExpectedRepository: "https://gitlab.invalid/group/project",
		ExpectedCommit:     strings.Repeat("b", 40), ExpectedRef: "refs/tags/v9.9.9", ExpectedPipeline: "123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reportHasFinding(report, ProvenanceMismatchID) || !reportHasFinding(report, ReleaseTagMismatchID) {
		t.Fatalf("missing mismatch findings: %+v", report.Findings)
	}
}

func TestVerifyReportsMissingProvenanceForExpectedIdentity(t *testing.T) {
	t.Parallel()

	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`)},
	})
	report, err := Verify(context.Background(), Options{
		Artifact: artifact, ExpectedCommit: strings.Repeat("c", 40),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reportHasFinding(report, ProvenanceMismatchID) {
		t.Fatalf("missing provenance finding: %+v", report.Findings)
	}
}

func TestReleaseTagCheckIgnoresBareBranchName(t *testing.T) {
	t.Parallel()

	files := []FileRecord{{
		Path: "package/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`),
	}}
	if findings := releaseTagFindings(files, "main"); len(findings) != 0 {
		t.Fatalf("bare branch produced release-tag findings: %+v", findings)
	}
}

func writeProvenanceFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provenance.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
