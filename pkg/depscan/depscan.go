// Package depscan integrates depx malicious-package auditing with GoGatoZ
// findings without installing or executing any dependency.
package depscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const (
	MaliciousDependencyID   = analyze.MaliciousDependencyID
	QuarantinedDependencyID = analyze.QuarantinedDependencyID
)

// AuditFinding is a package verdict emitted by the native depx bridge.
type AuditFinding struct {
	Verdict    string    `json:"verdict"`
	Ecosystem  string    `json:"ecosystem"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	IDs        []string  `json:"ids,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Published  time.Time `json:"published_at,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	Source     string    `json:"source,omitempty"`
	SourceType string    `json:"source_type,omitempty"`
	Lockfile   string    `json:"lockfile,omitempty"`
	ProjectDir string    `json:"project_dir,omitempty"`
	ProjectURL string    `json:"project_url,omitempty"`
	PackageURL string    `json:"package_url,omitempty"`
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

type sbomAuditor interface {
	AuditSBOM(context.Context, []string, string) (AuditResult, []byte, error)
}

// Report combines depx counts with GoGatoZ-native findings.
type Report struct {
	Engine       string                `json:"engine"`
	Paths        []string              `json:"paths"`
	Lockfiles    []Lockfile            `json:"lockfiles"`
	Dependencies int                   `json:"dependencies"`
	Summary      AuditSummary          `json:"summary"`
	Packages     []AuditFinding        `json:"packages,omitempty"`
	Components   []DependencyComponent `json:"components,omitempty"`
	Findings     []analyze.Finding     `json:"findings"`
	Warnings     []string              `json:"warnings,omitempty"`
	Mode         string                `json:"mode,omitempty"`
	DurationMS   int64                 `json:"duration_ms,omitempty"`
	SBOMPath     string                `json:"sbom_path,omitempty"`
}

// Scanner maps native depx verdicts to GoGatoZ's finding model.
type Scanner struct {
	auditor         Auditor
	auditMu         sync.Mutex
	archiveLimits   ArchiveLimits
	releaseProvider ReleaseProvider
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
	s.auditMu.Lock()
	auditResult, err := s.auditor.Audit(ctx, paths)
	s.auditMu.Unlock()
	if err != nil {
		return Report{}, fmt.Errorf("audit dependencies with depx: %w", err)
	}

	report := reportFromAuditResult(auditResult)
	slog.Info("completed dependency metadata scan", "engine", "depx",
		"dependencies", report.Dependencies, "findings", len(report.Findings))
	return report, nil
}

// ScanSBOM audits metadata once and returns depx's native SBOM serialization.
func (s *Scanner) ScanSBOM(ctx context.Context, paths []string, format string) (Report, []byte, error) {
	if s == nil || s.auditor == nil {
		return Report{}, nil, errors.New("scan dependencies: nil depx auditor")
	}
	exporter, ok := s.auditor.(sbomAuditor)
	if !ok {
		return Report{}, nil, errors.New("scan dependencies: native depx SBOM export unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	paths = normalizePaths(paths)
	format = strings.ToLower(strings.TrimSpace(format))

	slog.Info("starting dependency metadata scan with SBOM export", "engine", "depx",
		"paths", len(paths), "format", format)
	s.auditMu.Lock()
	auditResult, sbom, err := exporter.AuditSBOM(ctx, paths, format)
	s.auditMu.Unlock()
	if err != nil {
		return Report{}, nil, fmt.Errorf("audit dependencies with depx: %w", err)
	}
	report := reportFromAuditResult(auditResult)
	slog.Info("completed dependency metadata scan with SBOM export", "engine", "depx",
		"dependencies", report.Dependencies, "findings", len(report.Findings), "format", format)
	return report, sbom, nil
}

func reportFromAuditResult(auditResult AuditResult) Report {
	findings := make([]analyze.Finding, 0, len(auditResult.Findings))
	packages := make([]AuditFinding, 0, len(auditResult.Findings))
	for _, auditFinding := range auditResult.Findings {
		finding, ok := mapFinding(auditFinding)
		if !ok {
			slog.Warn("ignoring unsupported depx verdict", "verdict", auditFinding.Verdict,
				"ecosystem", auditFinding.Ecosystem, "package", auditFinding.Name)
			continue
		}
		findings = append(findings, finding)
		packages = append(packages, auditFinding)
	}

	return Report{
		Engine:       "depx",
		Paths:        append([]string(nil), auditResult.Paths...),
		Lockfiles:    append([]Lockfile(nil), auditResult.Lockfiles...),
		Dependencies: auditResult.Dependencies,
		Summary:      auditResult.Summary,
		Packages:     packages,
		Findings:     findings,
		Mode:         auditResult.Mode,
		DurationMS:   auditResult.DurationMS,
		SBOMPath:     auditResult.SBOMPath,
	}
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
