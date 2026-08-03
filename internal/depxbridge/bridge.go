// Package depxbridge exposes the minimum stable surface GoGatoZ needs from
// depx. The upstream project currently keeps its native audit API internal, so
// this nested module deliberately uses a depx-prefixed module path to consume
// that API in-process without invoking the depx CLI.
package depxbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/registry"
)

const defaultVersion = "gogatoz"

const maxSBOMBytes = 64 << 20

var ErrClosed = errors.New("depx auditor is closed")

// Options configures the native depx auditor.
type Options struct {
	CacheDir string
	Timeout  time.Duration
	Version  string
}

// Finding is a depx verdict returned to the parent GoGatoZ module.
type Finding struct {
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

// Lockfile describes a dependency source discovered by depx.
type Lockfile struct {
	Path         string
	Type         string
	Ecosystem    string
	Dependencies int
}

// Summary contains depx verdict counts.
type Summary struct {
	Lockfiles           int
	Total               int
	Malicious           int
	Quarantined         int
	Suspicious          int
	Clean               int
	SkippedPlaceholders int
}

// Result contains the mapped native depx audit result.
type Result struct {
	Paths        []string
	Lockfiles    []Lockfile
	Dependencies int
	Summary      Summary
	Findings     []Finding
	Mode         string
	DurationMS   int64
	SBOMPath     string
}

// Auditor owns a native depx audit service and intelligence provider.
type Auditor struct {
	service   *audit.Service
	provider  intel.Provider
	version   string
	closeMu   sync.RWMutex
	closed    bool
	closeOnce sync.Once
}

// New constructs an in-process depx auditor pinned by this module's go.mod.
func New(opts Options) (*Auditor, error) {
	cfg := config.Default()
	if cacheDir := strings.TrimSpace(opts.CacheDir); cacheDir != "" {
		cfg.CacheDir = cacheDir
	}
	if opts.Timeout > 0 {
		cfg.Timeout = opts.Timeout
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create depx cache directory: %w", err)
	}

	version := strings.TrimSpace(opts.Version)
	if version == "" {
		version = defaultVersion
	}
	provider, err := intel.New(version, cfg)
	if err != nil {
		return nil, fmt.Errorf("initialize depx intelligence provider: %w", err)
	}
	reg := registry.NewClient("gogatoz-depx/"+version, cfg.Timeout)

	return &Auditor{
		service:  audit.NewService(provider, reg, cfg.CacheDir),
		provider: provider,
		version:  version,
	}, nil
}

// Audit discovers supported lockfiles and SBOMs and matches their dependencies
// with depx malicious-package intelligence.
func (a *Auditor) Audit(ctx context.Context, paths []string) (Result, error) {
	return a.audit(ctx, paths, audit.Options{})
}

// AuditSBOM audits dependencies once and returns depx's native CycloneDX or
// SPDX serialization alongside the normal verdict result.
func (a *Auditor) AuditSBOM(ctx context.Context, paths []string, format string) (Result, []byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "cyclonedx" && format != "spdx" {
		return Result{}, nil, fmt.Errorf("unsupported depx SBOM format %q", format)
	}
	tempDir, err := os.MkdirTemp("", "gogatoz-depx-sbom-")
	if err != nil {
		return Result{}, nil, fmt.Errorf("create depx SBOM workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	exportPath := filepath.Join(tempDir, format+".json")
	result, err := a.audit(ctx, paths, audit.Options{
		SBOMExport:      exportPath,
		SBOMFormat:      format,
		SBOMToolVersion: a.version,
	})
	if err != nil {
		return Result{}, nil, err
	}
	file, err := os.Open(exportPath)
	if err != nil {
		return Result{}, nil, fmt.Errorf("open native depx SBOM: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSBOMBytes+1))
	if err != nil {
		return Result{}, nil, fmt.Errorf("read native depx SBOM: %w", err)
	}
	if len(data) > maxSBOMBytes {
		return Result{}, nil, fmt.Errorf("native depx SBOM exceeds %d bytes", maxSBOMBytes)
	}
	return result, data, nil
}

func (a *Auditor) audit(ctx context.Context, paths []string, opts audit.Options) (Result, error) {
	if a == nil {
		return Result{}, errors.New("audit dependencies: nil depx auditor")
	}
	a.closeMu.RLock()
	defer a.closeMu.RUnlock()
	if a.closed {
		return Result{}, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	slog.Info("starting native depx dependency audit", "paths", len(paths))
	result, err := a.service.AuditWithOptions(ctx, paths, opts)
	if err != nil {
		return Result{}, fmt.Errorf("run native depx audit: %w", err)
	}
	mapped := mapResult(result)
	slog.Info("completed native depx dependency audit",
		"dependencies", mapped.Dependencies,
		"findings", len(mapped.Findings),
		"duration_ms", mapped.DurationMS,
	)
	return mapped, nil
}

// Close waits for any bounded depx background inventory refresh exactly once.
func (a *Auditor) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		a.closeMu.Lock()
		a.closed = true
		a.closeMu.Unlock()
		if a.provider != nil {
			a.provider.WaitBackgroundSync()
		}
	})
}

func mapResult(result *audit.Result) Result {
	if result == nil {
		return Result{}
	}
	mapped := Result{
		Paths:        append([]string(nil), result.Paths...),
		Lockfiles:    make([]Lockfile, 0, len(result.Lockfiles)),
		Dependencies: result.Dependencies,
		Summary: Summary{
			Lockfiles:           result.Summary.Lockfiles,
			Total:               result.Summary.Total,
			Malicious:           result.Summary.Malicious,
			Quarantined:         result.Summary.Quarantined,
			Suspicious:          result.Summary.Suspicious,
			Clean:               result.Summary.Clean,
			SkippedPlaceholders: result.Summary.SkippedPlaceholders,
		},
		Findings:   make([]Finding, 0, len(result.Findings)),
		Mode:       result.Mode,
		DurationMS: result.DurationMS,
		SBOMPath:   result.SBOMPath,
	}
	for _, lockfile := range result.Lockfiles {
		mapped.Lockfiles = append(mapped.Lockfiles, Lockfile{
			Path: lockfile.Path, Type: lockfile.Type, Ecosystem: lockfile.Ecosystem,
			Dependencies: lockfile.Dependencies,
		})
	}
	for _, finding := range result.Findings {
		mapped.Findings = append(mapped.Findings, Finding{
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
