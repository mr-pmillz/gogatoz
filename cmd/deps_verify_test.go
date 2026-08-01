package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/artifactverify"
	"github.com/spf13/cobra"
)

func TestRunDependencyVerifySupportsReports(t *testing.T) {
	originalVerifier := verifyPackageArtifact
	originalFormat := verifyFormat
	originalOutput := verifyOutput
	originalFail := verifyFailOnFindings
	defer func() {
		verifyPackageArtifact = originalVerifier
		verifyFormat = originalFormat
		verifyOutput = originalOutput
		verifyFailOnFindings = originalFail
	}()

	fixture := artifactverify.Report{
		Artifact: "fixture.tgz", ArtifactType: "tar.gz", Files: 2, ExpandedBytes: 42,
		Findings: []analyze.Finding{{
			ID: analyze.PackageExecutionTriggerID, Severity: analyze.SeverityHigh,
			Title: "Package execution trigger", SourceFile: "package/package.json",
		}},
	}
	var got artifactverify.Options
	verifyPackageArtifact = func(_ context.Context, opts artifactverify.Options) (artifactverify.Report, error) {
		got = opts
		return fixture, nil
	}
	verifyArtifact = " fixture.tgz "
	verifySource = " source.tgz "
	verifyProvenance = " provenance.json "
	verifyExpectedRepository = " https://gitlab.invalid/group/project "
	verifyExpectedCommit = " abc123 "
	verifyExpectedRef = " refs/tags/v1.2.3 "
	verifyExpectedPipeline = " 987 "
	verifyOutput = ""
	verifyFailOnFindings = false
	verifyMaxDownloadBytes = 1024
	verifyMaxExpandedBytes = 2048
	verifyMaxFileBytes = 512
	verifyMaxFiles = 25

	for _, format := range []string{fmtText, fmtJSON, fmtSARIF, fmtGLSAST} {
		t.Run(format, func(t *testing.T) {
			verifyFormat = format
			var output bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&output)
			command.SetErr(&output)
			if err := runDependencyVerify(command, nil); err != nil {
				t.Fatalf("runDependencyVerify: %v", err)
			}
			assertArtifactVerifyOutput(t, format, output.Bytes())
		})
	}
	if got.Artifact != "fixture.tgz" || got.Source != "source.tgz" || got.Provenance != "provenance.json" {
		t.Fatalf("verifier inputs = %+v", got)
	}
	if got.ExpectedRepository != "https://gitlab.invalid/group/project" || got.ExpectedCommit != "abc123" ||
		got.ExpectedRef != "refs/tags/v1.2.3" || got.ExpectedPipeline != "987" {
		t.Fatalf("verifier expectations = %+v", got)
	}
	if got.Limits.MaxDownloadBytes != 1024 || got.Limits.MaxExpandedBytes != 2048 ||
		got.Limits.MaxFileBytes != 512 || got.Limits.MaxFiles != 25 {
		t.Fatalf("verifier limits = %+v", got.Limits)
	}
}

func TestRunDependencyVerifyFailOnFindings(t *testing.T) {
	originalVerifier := verifyPackageArtifact
	originalFail := verifyFailOnFindings
	defer func() {
		verifyPackageArtifact = originalVerifier
		verifyFailOnFindings = originalFail
	}()
	verifyPackageArtifact = func(context.Context, artifactverify.Options) (artifactverify.Report, error) {
		return artifactverify.Report{Findings: []analyze.Finding{{ID: analyze.PackageExecutableID}}}, nil
	}
	verifyArtifact = "fixture.tgz"
	verifyFormat = fmtJSON
	verifyOutput = ""
	verifyFailOnFindings = true
	command := &cobra.Command{}
	command.SetOut(&bytes.Buffer{})
	err := runDependencyVerify(command, nil)
	if !errors.Is(err, ErrArtifactFindings) {
		t.Fatalf("runDependencyVerify error = %v, want %v", err, ErrArtifactFindings)
	}
}

func assertArtifactVerifyOutput(t *testing.T, format string, output []byte) {
	t.Helper()
	switch format {
	case fmtJSON:
		var report artifactverify.Report
		if err := json.Unmarshal(output, &report); err != nil || report.Files != 2 {
			t.Fatalf("JSON output = %q, error = %v", output, err)
		}
	case fmtSARIF:
		var report sarifLog
		if err := json.Unmarshal(output, &report); err != nil || len(report.Runs[0].Results) != 1 {
			t.Fatalf("SARIF output = %q, error = %v", output, err)
		}
	case fmtGLSAST:
		var report glsastReport
		if err := json.Unmarshal(output, &report); err != nil || len(report.Vulnerabilities) != 1 {
			t.Fatalf("GitLab SAST output = %q, error = %v", output, err)
		}
	default:
		if !bytes.Contains(output, []byte(analyze.PackageExecutionTriggerID)) {
			t.Fatalf("text output = %q", output)
		}
	}
}
