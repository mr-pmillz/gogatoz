package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/depscan"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

type fakeDependencyScanRunner struct {
	report depscan.Report
	err    error
	paths  []string
	closed bool
}

func (s *fakeDependencyScanRunner) Scan(_ context.Context, paths []string) (depscan.Report, error) {
	s.paths = append([]string(nil), paths...)
	return s.report, s.err
}

func (s *fakeDependencyScanRunner) ScanGitLabProject(
	_ context.Context,
	_ *gitlabx.Client,
	_ int64,
	_ string,
) (depscan.Report, error) {
	return s.report, s.err
}

func (s *fakeDependencyScanRunner) Close() { s.closed = true }

func dependencyReportFixture() depscan.Report {
	return depscan.Report{
		Engine: "depx", Dependencies: 1,
		Summary: depscan.AuditSummary{Lockfiles: 1, Total: 1, Malicious: 1},
		Findings: []analyze.Finding{{
			ID: analyze.MaliciousDependencyID, Severity: analyze.SeverityCritical,
			Title: "Known malicious dependency", Evidence: "synthetic metadata match",
			SourceFile: "bom.cdx.json",
		}},
	}
}

func TestRunDependencyAuditSupportsAllFormats(t *testing.T) {
	originalFactory := newDependencyScanner
	originalFormat := depsFormat
	originalOutput := depsOutput
	originalCache := depsCacheDir
	originalTimeout := depsTimeout
	originalFail := depsFailOnFindings
	originalJSON := outputJSON
	defer func() {
		newDependencyScanner = originalFactory
		depsFormat = originalFormat
		depsOutput = originalOutput
		depsCacheDir = originalCache
		depsTimeout = originalTimeout
		depsFailOnFindings = originalFail
		outputJSON = originalJSON
	}()

	depsOutput = ""
	depsCacheDir = " /tmp/gogatoz-depx-cache "
	depsTimeout = "11s"
	depsFailOnFindings = false
	outputJSON = false

	for _, format := range []string{fmtText, fmtJSON, fmtSARIF, fmtGLSAST} {
		t.Run(format, func(t *testing.T) {
			runner := &fakeDependencyScanRunner{report: dependencyReportFixture()}
			var gotOptions depscan.Options
			newDependencyScanner = func(opts depscan.Options) (dependencyScanRunner, error) {
				gotOptions = opts
				return runner, nil
			}
			depsFormat = format
			var output bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&output)
			command.SetErr(&output)

			if err := runDependencyAudit(command, []string{"  /repo  ", ""}); err != nil {
				t.Fatalf("runDependencyAudit: %v", err)
			}
			if len(runner.paths) != 1 || runner.paths[0] != "/repo" {
				t.Fatalf("paths = %v, want [/repo]", runner.paths)
			}
			if !runner.closed {
				t.Fatal("dependency scanner was not closed")
			}
			if gotOptions.CacheDir != "/tmp/gogatoz-depx-cache" || gotOptions.Timeout != 11*time.Second {
				t.Fatalf("scanner options = %+v", gotOptions)
			}

			assertDependencyOutput(t, format, output.Bytes())
		})
	}
}

func assertDependencyOutput(t *testing.T, format string, output []byte) {
	t.Helper()
	switch format {
	case fmtJSON:
		var report depscan.Report
		if err := json.Unmarshal(output, &report); err != nil || report.Engine != "depx" {
			t.Fatalf("JSON output = %q, error = %v", output, err)
		}
	case fmtSARIF:
		var report sarifLog
		if err := json.Unmarshal(output, &report); err != nil || len(report.Runs) != 1 {
			t.Fatalf("SARIF output = %q, error = %v", output, err)
		}
	case fmtGLSAST:
		var report glsastReport
		if err := json.Unmarshal(output, &report); err != nil || len(report.Vulnerabilities) != 1 {
			t.Fatalf("GitLab SAST output = %q, error = %v", output, err)
		}
	default:
		if text := string(output); !strings.Contains(text, "Dependencies: 1") || !strings.Contains(text, "MALICIOUS_DEPENDENCY") {
			t.Fatalf("text output = %q", output)
		}
	}
}

func TestRunDependencyAuditFailOnFindings(t *testing.T) {
	originalFactory := newDependencyScanner
	originalFail := depsFailOnFindings
	originalFormat := depsFormat
	defer func() {
		newDependencyScanner = originalFactory
		depsFailOnFindings = originalFail
		depsFormat = originalFormat
	}()

	newDependencyScanner = func(depscan.Options) (dependencyScanRunner, error) {
		return &fakeDependencyScanRunner{report: dependencyReportFixture()}, nil
	}
	depsFailOnFindings = true
	depsFormat = fmtJSON
	command := &cobra.Command{}
	command.SetOut(&bytes.Buffer{})

	if err := runDependencyAudit(command, nil); !errors.Is(err, ErrDependencyFindings) {
		t.Fatalf("error = %v, want ErrDependencyFindings", err)
	}
}

func TestDependencyAuditCommandIsRegistered(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"deps", "audit"})
	if err != nil {
		t.Fatalf("find deps audit: %v", err)
	}
	if command == nil || command.Name() != "audit" {
		t.Fatalf("command = %v, want deps audit", command)
	}
}
