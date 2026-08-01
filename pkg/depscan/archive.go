package depscan

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	defaultMaxArchiveBytes  = int64(100 << 20)
	defaultMaxExpandedBytes = int64(512 << 20)
	defaultMaxArchiveFiles  = 10_000
)

var (
	ErrUnsafeArchivePath       = errors.New("unsafe archive path")
	ErrUnsupportedArchiveEntry = errors.New("unsupported archive entry")
	ErrArchiveTooLarge         = errors.New("archive exceeds safety limit")
)

// ArchiveLimits bounds untrusted repository archives before dependency scan.
type ArchiveLimits struct {
	MaxArchiveBytes  int64
	MaxExpandedBytes int64
	MaxFiles         int
}

func (l ArchiveLimits) withDefaults() ArchiveLimits {
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = defaultMaxArchiveBytes
	}
	if l.MaxExpandedBytes <= 0 {
		l.MaxExpandedBytes = defaultMaxExpandedBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = defaultMaxArchiveFiles
	}
	return l
}

type boundedReader struct {
	reader    io.Reader
	remaining int64
}

func (r *boundedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, ErrArchiveTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func extractTarGz(reader io.Reader, dest string, limits ArchiveLimits) error {
	if reader == nil {
		return errors.New("extract repository archive: nil reader")
	}
	limits = limits.withDefaults()
	compressed := &boundedReader{reader: reader, remaining: limits.MaxArchiveBytes + 1}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return fmt.Errorf("open repository gzip archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("open archive extraction root: %w", err)
	}
	defer func() { _ = root.Close() }()

	tarReader := tar.NewReader(gz)
	var expandedBytes int64
	entryCount := 0
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			if errors.Is(nextErr, ErrArchiveTooLarge) {
				return ErrArchiveTooLarge
			}
			return fmt.Errorf("read repository archive: %w", nextErr)
		}
		entryCount++
		if entryCount > limits.MaxFiles {
			return fmt.Errorf("%w: more than %d entries", ErrArchiveTooLarge, limits.MaxFiles)
		}

		if err := extractArchiveEntry(root, tarReader, header, &expandedBytes, limits); err != nil {
			return err
		}
	}
}

func extractArchiveEntry(
	root *os.Root,
	tarReader *tar.Reader,
	header *tar.Header,
	expandedBytes *int64,
	limits ArchiveLimits,
) error {
	// GitLab archive exports may begin with a POSIX PAX global header. It only
	// supplies metadata to archive/tar and has no filesystem representation.
	// Continue rejecting every other non-directory/non-regular entry below.
	if header.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	entryPath, err := safeArchivePath(header.Name)
	if err != nil {
		return err
	}
	if header.Typeflag == tar.TypeDir {
		if err := root.MkdirAll(entryPath, 0o700); err != nil {
			return fmt.Errorf("create archive directory %q: %w", header.Name, err)
		}
		return nil
	}
	if header.Typeflag != tar.TypeReg {
		return fmt.Errorf("%w: %q has tar type %d", ErrUnsupportedArchiveEntry, header.Name, header.Typeflag)
	}
	return extractRegularFile(root, tarReader, header, entryPath, expandedBytes, limits.MaxExpandedBytes)
}

func extractRegularFile(
	root *os.Root,
	tarReader *tar.Reader,
	header *tar.Header,
	entryPath string,
	expandedBytes *int64,
	maxExpandedBytes int64,
) error {
	if header.Size < 0 || header.Size > maxExpandedBytes-*expandedBytes {
		return fmt.Errorf("%w: expanded data exceeds %d bytes", ErrArchiveTooLarge, maxExpandedBytes)
	}
	*expandedBytes += header.Size
	if err := root.MkdirAll(filepath.Dir(entryPath), 0o700); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", header.Name, err)
	}
	file, err := root.OpenFile(entryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create archive file %q: %w", header.Name, err)
	}
	_, copyErr := io.CopyN(file, tarReader, header.Size)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("extract archive file %q: %w", header.Name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close archive file %q: %w", header.Name, closeErr)
	}
	return nil
}

func safeArchivePath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") {
		return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, name)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, name)
		}
	}
	cleaned := path.Clean(name)
	localPath := filepath.FromSlash(cleaned)
	if cleaned == "." || !filepath.IsLocal(localPath) {
		return "", fmt.Errorf("%w: %q", ErrUnsafeArchivePath, name)
	}
	return localPath, nil
}
