package depscan

import (
	"context"
	"fmt"
	"time"

	depxbridge "github.com/projectdiscovery/depx/gogatozbridge"
)

// Options configures a native depx scanner.
type Options struct {
	CacheDir      string
	Timeout       time.Duration
	Version       string
	ArchiveLimits ArchiveLimits
}

// New constructs a Scanner backed by depx's native Go implementation.
func New(opts Options) (*Scanner, error) {
	auditor, err := depxbridge.New(depxbridge.Options{
		CacheDir: opts.CacheDir,
		Timeout:  opts.Timeout,
		Version:  opts.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("create native depx scanner: %w", err)
	}
	scanner := NewScanner(&nativeAuditor{auditor: auditor})
	scanner.archiveLimits = opts.ArchiveLimits
	return scanner, nil
}

type nativeAuditor struct {
	auditor *depxbridge.Auditor
}

func (a *nativeAuditor) Audit(ctx context.Context, paths []string) (AuditResult, error) {
	result, err := a.auditor.Audit(ctx, paths)
	if err != nil {
		return AuditResult{}, err
	}
	return mapNativeResult(result), nil
}

func (a *nativeAuditor) AuditSBOM(ctx context.Context, paths []string, format string) (AuditResult, []byte, error) {
	result, sbom, err := a.auditor.AuditSBOM(ctx, paths, format)
	if err != nil {
		return AuditResult{}, nil, err
	}
	return mapNativeResult(result), sbom, nil
}

func mapNativeResult(result depxbridge.Result) AuditResult {
	mapped := AuditResult{
		Paths:        append([]string(nil), result.Paths...),
		Lockfiles:    make([]Lockfile, 0, len(result.Lockfiles)),
		Dependencies: result.Dependencies,
		Summary: AuditSummary{
			Lockfiles: result.Summary.Lockfiles, Total: result.Summary.Total,
			Malicious: result.Summary.Malicious, Quarantined: result.Summary.Quarantined,
			Suspicious: result.Summary.Suspicious, Clean: result.Summary.Clean,
			SkippedPlaceholders: result.Summary.SkippedPlaceholders,
		},
		Findings: make([]AuditFinding, 0, len(result.Findings)),
		Mode:     result.Mode, DurationMS: result.DurationMS, SBOMPath: result.SBOMPath,
	}
	for _, lockfile := range result.Lockfiles {
		mapped.Lockfiles = append(mapped.Lockfiles, Lockfile{
			Path: lockfile.Path, Type: lockfile.Type, Ecosystem: lockfile.Ecosystem,
			Dependencies: lockfile.Dependencies,
		})
	}
	for _, finding := range result.Findings {
		mapped.Findings = append(mapped.Findings, AuditFinding{
			Verdict: finding.Verdict, Ecosystem: finding.Ecosystem,
			Name: finding.Name, Version: finding.Version,
			IDs: append([]string(nil), finding.IDs...), Summary: finding.Summary,
			Published: finding.Published, ModifiedAt: finding.ModifiedAt,
			Source: finding.Source, SourceType: finding.SourceType,
			Lockfile: finding.Lockfile, ProjectDir: finding.ProjectDir,
			ProjectURL: finding.ProjectURL, PackageURL: finding.PackageURL,
		})
	}
	return mapped
}

func (a *nativeAuditor) Close() {
	if a != nil && a.auditor != nil {
		a.auditor.Close()
	}
}
