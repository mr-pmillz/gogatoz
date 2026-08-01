package artifactverify

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifySupportsWheelZIP(t *testing.T) {
	t.Parallel()

	var body bytes.Buffer
	zw := zip.NewWriter(&body)
	file, err := zw.Create("gogatoz_fixture/import_hook.pth")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("import synthetic_fixture\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gogatoz_fixture-1.0.0-py3-none-any.whl")
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Verify(context.Background(), Options{Artifact: path})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.ArtifactType != "zip" || !reportHasFinding(report, "PACKAGE_EXECUTION_TRIGGER") {
		t.Fatalf("wheel report = %+v", report)
	}
}

func TestVerifySupportsRubyGemDataArchive(t *testing.T) {
	t.Parallel()

	dataArchive := syntheticTarGzBytes(t, []syntheticArchiveFile{
		{path: "lib/gogatoz_fixture.rb", content: []byte("module GogatozFixture; end\n")},
		{path: "bin/gogatoz-fixture", content: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755},
	})
	var gem bytes.Buffer
	tw := tar.NewWriter(&gem)
	if err := tw.WriteHeader(&tar.Header{Name: "data.tar.gz", Mode: 0o644, Size: int64(len(dataArchive)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(dataArchive); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gogatoz_fixture-1.0.0.gem")
	if err := os.WriteFile(path, gem.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Verify(context.Background(), Options{Artifact: path})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.ArtifactType != "gem" || report.Files != 2 {
		t.Fatalf("gem report = %+v", report)
	}
}

func syntheticTarGzBytes(t *testing.T, files []syntheticArchiveFile) []byte {
	t.Helper()
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: file.path, Mode: file.mode, Size: int64(len(file.content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(file.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
