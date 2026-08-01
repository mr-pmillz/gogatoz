// Package depscan integrates depx malicious-package auditing with GoGatoZ
// findings without installing or executing any dependency.
package depscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const (
	MaliciousDependencyID   = analyze.MaliciousDependencyID
	QuarantinedDependencyID = analyze.QuarantinedDependencyID
)

// AuditFinding is a package verdict emitted by the native depx bridge.
type AuditFinding struct {
	Verdict    string
	Ecosystem  string
	Name       string
	Version    string
	IDs        []string
	Summary    string
	Published  time.Time
	ModifiedAt time.Time
	Source     string
	SourceType string
	Lockfile   string
	ProjectDir string
	ProjectURL string
	PackageURL string
}

// Lockfile describes a supported lockfile or SBOM discovered by depx.
type Lockfile struct {
	Path         string
	Type         string
	Ecosystem    string
	Dependencies int
}

// AuditSummary contains depx verdict counts.
type AuditSummary struct {
	Lockfiles           int
	Total               int
	Malicious           int
	Quarantined         int
	Suspicious          int
	Clean               int
	SkippedPlaceholders int
}

// AuditResult is the implementation-independent output from a depx audit.
type AuditResult struct {
	Paths        []string
	Lockfiles    []Lockfile
	Dependencies int
	Summary      AuditSummary
	Findings     []AuditFinding
	Mode         string
	DurationMS   int64
	SBOMPath     string
}

// Auditor is the small native depx surface consumed by Scanner.
type Auditor interface {
	Audit(context.Context, []string) (AuditResult, error)
	Close()
}

// Report combines depx counts with GoGatoZ-native findings.
type Report struct {
	Engine       string            `json:"engine"`
	Paths        []string          `json:"paths"`
	Lockfiles    []Lockfile        `json:"lockfiles"`
	Dependencies int               `json:"dependencies"`
	Summary      AuditSummary      `json:"summary"`
	Findings     []analyze.Finding `json:"findings"`
	Mode         string            `json:"mode,omitempty"`
	DurationMS   int64             `json:"duration_ms,omitempty"`
	SBOMPath     string            `json:"sbom_path,omitempty"`
}

// Scanner maps native depx verdicts to GoGatoZ's finding model.
type Scanner struct {
	auditor Auditor
}

func NewScanner(auditor Auditor) *Scanner {
	return &Scanner{auditor: auditor}
}

// Scan audits dependency metadata only. It never invokes a package manager or
// executes package contents or lifecycle scripts.
func (s *Scanner) Scan(ctx context.Context, paths []string) (Report, error) {
	if s == nil || s.auditor == nil {
		return Report{}, errors.New("scan dependencies: nil depx auditor")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	paths = normalizePaths(paths)

	slog.Info("starting dependency metadata scan", "engine", "depx", "paths", len(paths))
	auditResult, err := s.auditor.Audit(ctx, paths)
	if err != nil {
		return Report{}, fmt.Errorf("audit dependencies with depx: %w", err)
	}

	findings := make([]analyze.Finding, 0, len(auditResult.Findings))
	for _, auditFinding := range auditResult.Findings {
		finding, ok := mapFinding(auditFinding)
		if !ok {
			slog.Warn("ignoring unsupported depx verdict", "verdict", auditFinding.Verdict,
				"ecosystem", auditFinding.Ecosystem, "package", auditFinding.Name)
			continue
		}
		findings = append(findings, finding)
	}

	report := Report{
		Engine:       "depx",
		Paths:        append([]string(nil), auditResult.Paths...),
		Lockfiles:    append([]Lockfile(nil), auditResult.Lockfiles...),
		Dependencies: auditResult.Dependencies,
		Summary:      auditResult.Summary,
		Findings:     findings,
		Mode:         auditResult.Mode,
		DurationMS:   auditResult.DurationMS,
		SBOMPath:     auditResult.SBOMPath,
	}
	slog.Info("completed dependency metadata scan", "engine", "depx",
		"dependencies", report.Dependencies, "findings", len(report.Findings))
	return report, nil
}

// Close releases the underlying depx provider.
func (s *Scanner) Close() {
	if s != nil && s.auditor != nil {
		s.auditor.Close()
	}
}

func normalizePaths(paths []string) []string {
	normalized := make([]string, 0, len(paths))
	for _, inputPath := range paths {
		if inputPath = strings.TrimSpace(inputPath); inputPath != "" {
			normalized = append(normalized, inputPath)
		}
	}
	if len(normalized) == 0 {
		return []string{"."}
	}
	return normalized
}

func mapFinding(finding AuditFinding) (analyze.Finding, bool) {
	var id string
	switch strings.ToLower(strings.TrimSpace(finding.Verdict)) {
	case "malicious":
		id = MaliciousDependencyID
	case "quarantined":
		id = QuarantinedDependencyID
	default:
		return analyze.Finding{}, false
	}

	metadata := analyze.LookupFinding(id)
	title := id
	description := strings.TrimSpace(finding.Summary)
	recommendation := "Remove the affected dependency without installing or executing it."
	if metadata != nil {
		title = metadata.Title
		if description == "" {
			description = metadata.Description
		}
		recommendation = metadata.Remediation
	}
	if description == "" {
		description = "depx identified this dependency as " + strings.ToLower(strings.TrimSpace(finding.Verdict)) + "."
	}

	sourceFile := strings.TrimSpace(finding.Source)
	if sourceFile == "" {
		sourceFile = strings.TrimSpace(finding.Lockfile)
	}
	evidence := fmt.Sprintf("ecosystem=%s package=%s version=%s verdict=%s advisories=%s source=%s",
		finding.Ecosystem, finding.Name, finding.Version, finding.Verdict,
		strings.Join(finding.IDs, ","), sourceFile)

	return analyze.Finding{
		ID:             id,
		Severity:       analyze.SeverityCritical,
		Title:          title,
		Description:    description,
		Evidence:       evidence,
		Recommendation: recommendation,
		SourceFile:     sourceFile,
	}, true
}
