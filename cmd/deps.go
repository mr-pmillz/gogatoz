package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/depscan"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

var ErrDependencyFindings = errors.New("dependency findings detected")

var (
	depsFormat         string
	depsOutput         string
	depsCacheDir       string
	depsTimeout        string
	depsFailOnFindings bool
)

type dependencyScanRunner interface {
	Scan(context.Context, []string) (depscan.Report, error)
	ScanGitLabProject(context.Context, *gitlabx.Client, int64, string) (depscan.Report, error)
	Close()
}

var newDependencyScanner = func(opts depscan.Options) (dependencyScanRunner, error) {
	return depscan.New(opts)
}

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Audit dependency metadata with depx",
}

var depsAuditCmd = &cobra.Command{
	Use:   "audit [path...]",
	Short: "Find malicious or quarantined dependencies",
	Long: `Audit supported lockfiles and CycloneDX/SPDX SBOMs in-process with depx.

This command reads dependency metadata only. It never invokes a package
manager and never installs or executes package contents or lifecycle scripts.`,
	Args: cobra.ArbitraryArgs,
	RunE: runDependencyAudit,
}

func init() {
	rootCmd.AddCommand(depsCmd)
	depsCmd.AddCommand(depsAuditCmd)
	depsAuditCmd.Flags().StringVarP(&depsFormat, "format", "f", fmtText, "Output format: text|json|sarif|glsast")
	depsAuditCmd.Flags().StringVarP(&depsOutput, "output", "o", "", "Write output to file (default: stdout)")
	depsAuditCmd.Flags().StringVar(&depsCacheDir, "cache-dir", "", "depx inventory cache directory")
	depsAuditCmd.Flags().StringVar(&depsTimeout, "timeout", "30s", "depx inventory and registry request timeout")
	depsAuditCmd.Flags().BoolVar(&depsFailOnFindings, "fail-on-findings", false, "Return a non-zero status when malicious or quarantined dependencies are found")
}

func runDependencyAudit(cmd *cobra.Command, args []string) error {
	paths := make([]string, 0, len(args))
	for _, inputPath := range args {
		if inputPath = strings.TrimSpace(inputPath); inputPath != "" {
			paths = append(paths, inputPath)
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}

	scanner, err := makeDependencyScanner(depsCacheDir, depsTimeout)
	if err != nil {
		return err
	}
	defer scanner.Close()

	report, err := scanner.Scan(cmd.Context(), paths)
	if err != nil {
		return err
	}
	writer, closer, err := openOutputWriter(cmd, depsOutput)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}
	if err := renderDependencyReport(writer, report, depsFormat); err != nil {
		return err
	}
	if depsFailOnFindings && len(report.Findings) > 0 {
		return fmt.Errorf("%w: %d", ErrDependencyFindings, len(report.Findings))
	}
	return nil
}

func makeDependencyScanner(cacheDir, timeoutValue string) (dependencyScanRunner, error) {
	timeoutValue = strings.TrimSpace(timeoutValue)
	var timeout time.Duration
	if timeoutValue != "" {
		parsed, err := time.ParseDuration(timeoutValue)
		if err != nil {
			return nil, fmt.Errorf("invalid depx timeout: %w", err)
		}
		if parsed <= 0 {
			return nil, errors.New("depx timeout must be greater than zero")
		}
		timeout = parsed
	}
	return newDependencyScanner(depscan.Options{
		CacheDir: strings.TrimSpace(cacheDir),
		Timeout:  timeout,
		Version:  version,
	})
}

func renderDependencyReport(writer io.Writer, report depscan.Report, format string) error {
	format = strings.ToLower(strings.TrimSpace(format))
	if outputJSON && format == "" {
		format = fmtJSON
	}
	if format == "" {
		format = fmtText
	}
	switch format {
	case fmtText:
		return renderDependencyText(writer, report)
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
		return fmt.Errorf("unsupported dependency report format %q", format)
	}
}

func renderDependencyText(writer io.Writer, report depscan.Report) error {
	if _, err := fmt.Fprintf(writer,
		"Dependency Audit (%s)\nDependencies: %d\nLockfiles/SBOMs: %d\nMalicious: %d\nQuarantined: %d\n",
		report.Engine, report.Dependencies, report.Summary.Lockfiles,
		report.Summary.Malicious, report.Summary.Quarantined,
	); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(writer, "- [%s] %s: %s (%s)\n",
			finding.Severity, finding.ID, finding.Title, finding.SourceFile); err != nil {
			return err
		}
	}
	return nil
}
