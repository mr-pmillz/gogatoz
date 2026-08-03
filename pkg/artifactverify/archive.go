package artifactverify

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

type archiveReport struct {
	format        string
	files         []FileRecord
	expandedBytes int64
}

func inspectArchive(data []byte, name string, limits Limits) (archiveReport, error) {
	lowerName := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lowerName, ".gem"):
		return inspectGem(data, limits)
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}):
		return inspectZIP(data, limits)
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return archiveReport{}, fmt.Errorf("%w: open gzip stream: %w", ErrUnsafeArchive, err)
		}
		defer gz.Close()
		return inspectTar(gz, "tar.gz", limits)
	case isTar(data):
		return inspectTar(bytes.NewReader(data), "tar", limits)
	default:
		return archiveReport{}, fmt.Errorf("%w: unsupported package archive format", ErrUnsafeArchive)
	}
}

func inspectZIP(data []byte, limits Limits) (archiveReport, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return archiveReport{}, fmt.Errorf("%w: open ZIP: %w", ErrUnsafeArchive, err)
	}
	report := archiveReport{format: "zip", files: make([]FileRecord, 0, len(reader.File))}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() {
			return archiveReport{}, unsafeEntry(file.Name, "ZIP member is not a regular file")
		}
		fileSize, err := boundedZIPSize(file.UncompressedSize64, limits.MaxFileBytes)
		if err != nil {
			return archiveReport{}, unsafeEntry(file.Name, "file exceeds per-file limit")
		}
		if err := addFileBudget(&report, file.Name, fileSize, limits); err != nil {
			return archiveReport{}, err
		}
		entry, err := file.Open()
		if err != nil {
			return archiveReport{}, fmt.Errorf("%w: open ZIP member %q: %w", ErrUnsafeArchive, file.Name, err)
		}
		content, readErr := readBounded(entry, limits.MaxFileBytes)
		closeErr := entry.Close()
		if readErr != nil {
			return archiveReport{}, unsafeEntry(file.Name, readErr.Error())
		}
		if closeErr != nil {
			return archiveReport{}, fmt.Errorf("%w: close ZIP member %q: %w", ErrUnsafeArchive, file.Name, closeErr)
		}
		report.files = append(report.files, makeFileRecord(file.Name, int64(file.Mode()), content))
	}
	return report, nil
}

func inspectTar(reader io.Reader, format string, limits Limits) (archiveReport, error) {
	report := archiveReport{format: format}
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archiveReport{}, fmt.Errorf("%w: read tar: %w", ErrUnsafeArchive, err)
		}
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		case tar.TypeReg, 0:
		default:
			return archiveReport{}, unsafeEntry(header.Name, fmt.Sprintf("tar type %d is not allowed", header.Typeflag))
		}
		if header.Size < 0 || header.Size > limits.MaxFileBytes {
			return archiveReport{}, unsafeEntry(header.Name, "file exceeds per-file limit")
		}
		if err := addFileBudget(&report, header.Name, header.Size, limits); err != nil {
			return archiveReport{}, err
		}
		content, err := readBounded(tarReader, limits.MaxFileBytes)
		if err != nil {
			return archiveReport{}, unsafeEntry(header.Name, err.Error())
		}
		if int64(len(content)) != header.Size {
			return archiveReport{}, unsafeEntry(header.Name, "truncated tar member")
		}
		report.files = append(report.files, makeFileRecord(header.Name, header.Mode, content))
	}
	return report, nil
}

func inspectGem(data []byte, limits Limits) (archiveReport, error) {
	outer := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := outer.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archiveReport{}, fmt.Errorf("%w: read gem: %w", ErrUnsafeArchive, err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != 0 {
			return archiveReport{}, unsafeEntry(header.Name, "gem member is not a regular file")
		}
		if err := validateArchivePath(header.Name); err != nil {
			return archiveReport{}, err
		}
		if header.Size < 0 || header.Size > limits.MaxDownloadBytes {
			return archiveReport{}, unsafeEntry(header.Name, "gem member exceeds download limit")
		}
		if path.Base(header.Name) != "data.tar.gz" {
			continue
		}
		body, err := readBounded(outer, limits.MaxDownloadBytes)
		if err != nil {
			return archiveReport{}, unsafeEntry(header.Name, err.Error())
		}
		nested, err := inspectArchive(body, "data.tar.gz", limits)
		if err != nil {
			return archiveReport{}, err
		}
		nested.format = "gem"
		return nested, nil
	}
	return archiveReport{}, fmt.Errorf("%w: gem has no data.tar.gz", ErrUnsafeArchive)
}

func addFileBudget(report *archiveReport, name string, size int64, limits Limits) error {
	if err := validateArchivePath(name); err != nil {
		return err
	}
	if len(report.files)+1 > limits.MaxFiles {
		return fmt.Errorf("%w: archive exceeds %d files", ErrUnsafeArchive, limits.MaxFiles)
	}
	if size > limits.MaxExpandedBytes-report.expandedBytes {
		return fmt.Errorf("%w: archive exceeds %d expanded bytes", ErrUnsafeArchive, limits.MaxExpandedBytes)
	}
	report.expandedBytes += size
	return nil
}

func boundedZIPSize(size uint64, maxBytes int64) (int64, error) {
	if size > uint64(maxBytes) { //nolint:gosec // maxBytes is validated as positive before archive inspection
		return 0, errors.New("ZIP member exceeds per-file limit")
	}
	return int64(size), nil //nolint:gosec // the comparison above proves size <= positive int64 maxBytes
}

func validateArchivePath(name string) error {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") {
		return unsafeEntry(name, "invalid path")
	}
	clean := path.Clean(name)
	if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return unsafeEntry(name, "path traversal or non-canonical path")
	}
	return nil
}

func makeFileRecord(name string, mode int64, content []byte) FileRecord {
	digest := sha256.Sum256(content)
	return FileRecord{
		Path: name, Size: int64(len(content)), Mode: mode,
		SHA256: fmt.Sprintf("%x", digest), Magic: detectMagic(content), content: content,
	}
}

func detectMagic(content []byte) string {
	switch {
	case len(content) >= 4 && bytes.Equal(content[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "elf"
	case len(content) >= 2 && bytes.Equal(content[:2], []byte{'M', 'Z'}):
		return "pe"
	case len(content) >= 4 && isMachOMagic(content[:4]):
		return "mach-o"
	case len(content) >= 2 && bytes.Equal(content[:2], []byte{'#', '!'}):
		return "script"
	case len(content) >= 4 && bytes.Equal(content[:4], []byte{'P', 'K', 3, 4}):
		return "zip"
	case len(content) >= 2 && content[0] == 0x1f && content[1] == 0x8b:
		return "gzip"
	case len(content) >= 8 && bytes.Equal(content[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
		return "png"
	default:
		return ""
	}
}

func isMachOMagic(prefix []byte) bool {
	known := [][4]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe},
	}
	for _, magic := range known {
		if bytes.Equal(prefix, magic[:]) {
			return true
		}
	}
	return false
}

func isTar(data []byte) bool {
	return len(data) >= 512 && bytes.Equal(data[257:262], []byte("ustar"))
}

func unsafeEntry(name, reason string) error {
	return fmt.Errorf("%w: %q: %s", ErrUnsafeArchive, name, reason)
}
