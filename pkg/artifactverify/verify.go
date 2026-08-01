// Package artifactverify performs bounded, static inspection of package
// archives and their source/provenance metadata. It never extracts or executes
// package contents.
package artifactverify

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

var (
	ErrUnsafeArchive = errors.New("unsafe package archive")
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
	Artifact   string
	Source     string
	Limits     Limits
	HTTPClient *http.Client
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
func Verify(ctx context.Context, opts Options) (Report, error) {
	artifact := strings.TrimSpace(opts.Artifact)
	if artifact == "" {
		return Report{}, errors.New("artifact path or URL is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	limits, err := normalizedLimits(opts.Limits)
	if err != nil {
		return Report{}, err
	}
	slog.Info("starting static package artifact verification", "artifact", artifact)
	data, err := readInput(ctx, artifact, limits.MaxDownloadBytes, opts.HTTPClient)
	if err != nil {
		return Report{}, fmt.Errorf("read package artifact: %w", err)
	}
	archive, err := inspectArchive(data, artifact, limits)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Artifact:       artifact,
		ArtifactType:   archive.format,
		ArtifactSHA256: fmt.Sprintf("%x", sha256.Sum256(data)),
		Files:          len(archive.files),
		ExpandedBytes:  archive.expandedBytes,
		Findings:       analyzeFiles(archive.files),
	}
	slog.Info("completed static package artifact verification",
		"files", report.Files, "expanded_bytes", report.ExpandedBytes, "findings", len(report.Findings))
	return report, nil
}

func normalizedLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaxDownloadBytes == 0 {
		limits.MaxDownloadBytes = defaults.MaxDownloadBytes
	}
	if limits.MaxExpandedBytes == 0 {
		limits.MaxExpandedBytes = defaults.MaxExpandedBytes
	}
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxFiles == 0 {
		limits.MaxFiles = defaults.MaxFiles
	}
	if limits.MaxDownloadBytes < 0 || limits.MaxExpandedBytes < 0 || limits.MaxFileBytes < 0 || limits.MaxFiles < 0 {
		return Limits{}, errors.New("artifact limits must be greater than zero")
	}
	return limits, nil
}

func readInput(ctx context.Context, input string, maxBytes int64, suppliedClient *http.Client) ([]byte, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("parse input: %w", err)
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		return fetchInput(ctx, parsed, maxBytes, suppliedClient)
	}
	if parsed.Scheme != "" {
		return nil, fmt.Errorf("unsupported input URL scheme %q", parsed.Scheme)
	}
	info, err := os.Lstat(input)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxBytes)
	}
	file, err := os.Open(input)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file, maxBytes)
}

func fetchInput(ctx context.Context, target *url.URL, maxBytes int64, suppliedClient *http.Client) ([]byte, error) {
	if target.User != nil || strings.TrimSpace(target.Hostname()) == "" {
		return nil, errors.New("artifact URL must not contain credentials and must have a host")
	}
	client := suppliedClient
	if client == nil {
		originalHost := strings.ToLower(target.Host)
		client = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many artifact redirects")
				}
				if strings.ToLower(req.URL.Host) != originalHost || req.URL.Scheme != target.Scheme {
					return errors.New("artifact redirect changed origin")
				}
				return nil
			},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	slog.Debug("fetching bounded package artifact", "host", target.Host, "max_bytes", maxBytes)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact server returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("artifact exceeds %d bytes", maxBytes)
	}
	return readBounded(resp.Body, maxBytes)
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxBytes)
	}
	return data, nil
}
