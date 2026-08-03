package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/artifactverify"
	"github.com/spf13/cobra"
)

var ErrArtifactFindings = errors.New("package artifact findings detected")

var (
	verifyArtifact           string
	verifySource             string
	verifyProvenance         string
	verifyExpectedRepository string
	verifyExpectedCommit     string
	verifyExpectedRef        string
	verifyExpectedPipeline   string
	verifyFormat             string
	verifyOutput             string
	verifyFailOnFindings     bool
	verifyMaxDownloadBytes   int64
	verifyMaxExpandedBytes   int64
	verifyMaxFileBytes       int64
	verifyMaxFiles           int
)

var verifyPackageArtifact = artifactverify.Verify

var depsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Statically verify a package artifact against source and provenance",
	Long: `Statically inspect a bounded package archive without installing or executing it.

Optionally compare the package with a reviewed source archive/tree and verify
SLSA/in-toto provenance against an expected repository, commit, ref, and
	pipeline identity.`,
	Args: cobra.NoArgs,
	RunE: runDependencyVerify,
}

func init() {
	depsCmd.AddCommand(depsVerifyCmd)
	limits := artifactverify.DefaultLimits()
	depsVerifyCmd.Flags().StringVar(&verifyArtifact, "artifact", "", "Package archive path or HTTP(S) URL (required)")
	depsVerifyCmd.Flags().StringVar(&verifySource, "source", "", "Reviewed source archive URL/path or local source directory")
	depsVerifyCmd.Flags().StringVar(&verifyProvenance, "provenance", "", "SLSA/in-toto provenance JSON URL or path")
	depsVerifyCmd.Flags().StringVar(&verifyExpectedRepository, "expected-repository", "", "Expected source repository identity")
	depsVerifyCmd.Flags().StringVar(&verifyExpectedCommit, "expected-commit", "", "Expected source commit")
	depsVerifyCmd.Flags().StringVar(&verifyExpectedRef, "expected-ref", "", "Expected branch or release tag ref")
	depsVerifyCmd.Flags().StringVar(&verifyExpectedPipeline, "expected-pipeline", "", "Expected publishing pipeline ID or invocation")
	depsVerifyCmd.Flags().StringVarP(&verifyFormat, "format", "f", fmtText, "Output format: text|json|sarif|glsast")
	depsVerifyCmd.Flags().StringVarP(&verifyOutput, "output", "o", "", "Write output to file (default: stdout)")
	depsVerifyCmd.Flags().BoolVar(&verifyFailOnFindings, "fail-on-findings", false, "Return a non-zero status when artifact findings are detected")
	depsVerifyCmd.Flags().Int64Var(&verifyMaxDownloadBytes, "max-download-bytes", limits.MaxDownloadBytes, "Maximum bytes per downloaded archive")
	depsVerifyCmd.Flags().Int64Var(&verifyMaxExpandedBytes, "max-expanded-bytes", limits.MaxExpandedBytes, "Maximum total expanded archive bytes")
	depsVerifyCmd.Flags().Int64Var(&verifyMaxFileBytes, "max-file-bytes", limits.MaxFileBytes, "Maximum expanded bytes per archive member")
	depsVerifyCmd.Flags().IntVar(&verifyMaxFiles, "max-files", limits.MaxFiles, "Maximum regular files per archive")
}

func runDependencyVerify(cmd *cobra.Command, _ []string) error {
	artifact := strings.TrimSpace(verifyArtifact)
	if artifact == "" {
		return errors.New("--artifact is required")
	}
	format := strings.ToLower(strings.TrimSpace(verifyFormat))
	if format != fmtText && format != fmtJSON && format != fmtSARIF && format != fmtGLSAST {
		return fmt.Errorf("unsupported artifact report format %q", format)
	}
	if verifyMaxDownloadBytes <= 0 || verifyMaxExpandedBytes <= 0 || verifyMaxFileBytes <= 0 || verifyMaxFiles <= 0 {
		return errors.New("artifact byte and file limits must be greater than zero")
	}
	report, err := runArtifactVerifier(cmd.Context(), artifactverify.Options{
		Artifact:           artifact,
		Source:             strings.TrimSpace(verifySource),
		Provenance:         strings.TrimSpace(verifyProvenance),
		ExpectedRepository: strings.TrimSpace(verifyExpectedRepository),
		ExpectedCommit:     strings.TrimSpace(verifyExpectedCommit),
		ExpectedRef:        strings.TrimSpace(verifyExpectedRef),
		ExpectedPipeline:   strings.TrimSpace(verifyExpectedPipeline),
		Limits: artifactverify.Limits{
			MaxDownloadBytes: verifyMaxDownloadBytes,
			MaxExpandedBytes: verifyMaxExpandedBytes,
			MaxFileBytes:     verifyMaxFileBytes,
			MaxFiles:         verifyMaxFiles,
		},
	})
	if err != nil {
		return err
	}
	writer, closer, err := openOutputWriter(cmd, verifyOutput)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}
	if err := renderArtifactVerifyReport(writer, report, format); err != nil {
		return err
	}
	if verifyFailOnFindings && len(report.Findings) > 0 {
		return fmt.Errorf("%w: %d", ErrArtifactFindings, len(report.Findings))
	}
	return nil
}

func runArtifactVerifier(ctx context.Context, options artifactverify.Options) (artifactverify.Report, error) {
	return verifyPackageArtifact(ctx, options)
}

func renderArtifactVerifyReport(writer io.Writer, report artifactverify.Report, format string) error {
	switch format {
	case fmtJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case fmtSARIF:
		return WriteSARIF(writer, report.Findings, version)
	case fmtGLSAST:
		now := time.Now()
		return WriteGLSAST(writer, report.Findings, version, now, now)
	default:
		return renderArtifactVerifyText(writer, report)
	}
}

func renderArtifactVerifyText(writer io.Writer, report artifactverify.Report) error {
	if _, err := fmt.Fprintf(writer,
		"Package Artifact Verification\nArtifact: %s\nType: %s\nFiles: %d\nExpanded bytes: %d\nFindings: %d\n",
		report.Artifact, report.ArtifactType, report.Files, report.ExpandedBytes, len(report.Findings),
	); err != nil {
		return err
	}
	if report.Source != "" {
		if _, err := fmt.Fprintf(writer, "Source: %s\nSource files: %d\n", report.Source, report.SourceFiles); err != nil {
			return err
		}
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(writer, "- [%s] %s: %s (%s)\n",
			finding.Severity, finding.ID, finding.Title, finding.SourceFile); err != nil {
			return err
		}
	}
	return nil
}
