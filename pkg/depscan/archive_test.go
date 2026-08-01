package depscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type tarEntry struct {
	name     string
	typeflag byte
	body     string
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Size:     int64(len(entry.body)),
			Typeflag: typeflag,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractTarGz_ExtractsRegularFilesInsideRoot(t *testing.T) {
	dest := t.TempDir()
	archive := makeTarGz(t, []tarEntry{{
		name: "project-deadbeef/bom.cdx.json",
		body: `{"bomFormat":"CycloneDX"}`,
	}})

	if err := extractTarGz(bytes.NewReader(archive), dest, ArchiveLimits{}); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "project-deadbeef", "bom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("content = %q", got)
	}
}

func TestExtractTarGz_RejectsPathTraversal(t *testing.T) {
	dest := t.TempDir()
	escape := filepath.Join(filepath.Dir(dest), "escape-package-lock.json")
	archive := makeTarGz(t, []tarEntry{{name: "../escape-package-lock.json", body: "unsafe"}})

	err := extractTarGz(bytes.NewReader(archive), dest, ArchiveLimits{})
	if !errors.Is(err, ErrUnsafeArchivePath) {
		t.Fatalf("error = %v, want ErrUnsafeArchivePath", err)
	}
	if _, statErr := os.Stat(escape); !os.IsNotExist(statErr) {
		t.Fatalf("archive wrote outside destination: %v", statErr)
	}
}

func TestExtractTarGz_RejectsLinks(t *testing.T) {
	dest := t.TempDir()
	archive := makeTarGz(t, []tarEntry{{name: "project/link", typeflag: tar.TypeSymlink}})

	err := extractTarGz(bytes.NewReader(archive), dest, ArchiveLimits{})
	if !errors.Is(err, ErrUnsupportedArchiveEntry) {
		t.Fatalf("error = %v, want ErrUnsupportedArchiveEntry", err)
	}
}

func TestExtractTarGz_EnforcesExpandedSizeLimit(t *testing.T) {
	dest := t.TempDir()
	archive := makeTarGz(t, []tarEntry{{name: "project/package-lock.json", body: "12345"}})

	err := extractTarGz(bytes.NewReader(archive), dest, ArchiveLimits{MaxExpandedBytes: 4})
	if !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("error = %v, want ErrArchiveTooLarge", err)
	}
}
