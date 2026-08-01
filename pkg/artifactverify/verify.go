// Package artifactverify performs bounded, static inspection of package
// archives and their source/provenance metadata. It never extracts or executes
// package contents.
package artifactverify

import (
	"context"
	"errors"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

var (
	ErrNotImplemented = errors.New("artifact verification is not implemented")
	ErrUnsafeArchive  = errors.New("unsafe package archive")
)

// Limits bounds all package downloads and archive expansion.
type Limits struct {
	MaxDownloadBytes int64
	MaxExpandedBytes int64
	MaxFileBytes     int64
	MaxFiles         int
}

// DefaultLimits returns conservative limits suitable for registry packages.
func DefaultLimits() Limits {
	return Limits{
		MaxDownloadBytes: 64 << 20,
		MaxExpandedBytes: 256 << 20,
		MaxFileBytes:     8 << 20,
		MaxFiles:         10_000,
	}
}

// Options configures one artifact verification operation.
type Options struct {
	Artifact string
	Source   string
	Limits   Limits
}

// FileRecord is static metadata collected from a regular archive member.
type FileRecord struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
	SHA256 string `json:"sha256"`
	Magic  string `json:"magic,omitempty"`

	content []byte
}

// Report is the machine-readable result of archive verification.
type Report struct {
	Artifact       string            `json:"artifact"`
	ArtifactType   string            `json:"artifact_type"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	Files          int               `json:"files"`
	ExpandedBytes  int64             `json:"expanded_bytes"`
	Findings       []analyze.Finding `json:"findings"`
}

// Verify statically inspects a local or remote package artifact.
func Verify(_ context.Context, _ Options) (Report, error) {
	return Report{}, ErrNotImplemented
}
