package cmd

import (
	"context"
	"errors"

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
	RunE: runDependencyVerify,
}

func init() {
	depsCmd.AddCommand(depsVerifyCmd)
}

func runDependencyVerify(_ *cobra.Command, _ []string) error {
	return errors.New("dependency artifact verification command is not implemented")
}

func runArtifactVerifier(ctx context.Context, options artifactverify.Options) (artifactverify.Report, error) {
	return verifyPackageArtifact(ctx, options)
}
