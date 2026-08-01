package artifactverify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyScansSyntheticArchiveWithoutExecution(t *testing.T) {
	t.Parallel()

	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/package.json", content: []byte(`{
  "name":"gogatoz-fixture","version":"1.2.3","main":"dist/index.js",
  "scripts":{"postinstall":"node synthetic-setup.js"}
}`)},
		{path: "package/binding.gyp", content: []byte(`{"targets":[]}`)},
		{path: "package/dist/index.js", content: []byte(
			`const h=[116,101,115,116,46,105,110,118,97,108,105,100].map((x)=>String.fromCharCode(x)).join('');` +
				`require('child_process').spawn('synthetic-noop',[],{detached:true});`)},
		{path: "package/fixture_loader.pth", content: []byte("import synthetic_fixture\n")},
		{path: "package/.vscode/tasks.json", content: []byte(`{"runOptions":{"runOn":"folderOpen"}}`)},
		{path: "package/config/synthetic.service", content: []byte("[Service]\nExecStart=/bin/true\n")},
		{path: "package/assets/image.png", content: append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 24)...), mode: 0o644},
	})

	report, err := Verify(context.Background(), Options{Artifact: artifact})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Files != 7 || report.ArtifactType != "tar.gz" || report.ArtifactSHA256 == "" {
		t.Fatalf("report metadata = %+v", report)
	}
	wantIDs := []string{
		"PACKAGE_EXECUTION_TRIGGER",
		"PACKAGE_PERSISTENCE_INDICATOR",
		"PACKAGE_EXECUTABLE_PAYLOAD",
		"PACKAGE_OBFUSCATION",
	}
	for _, id := range wantIDs {
		if !reportHasFinding(report, id) {
			t.Errorf("missing %s in findings: %+v", id, report.Findings)
		}
	}
}

func TestVerifyRejectsTraversalAndLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file syntheticArchiveFile
	}{
		{name: "traversal", file: syntheticArchiveFile{path: "package/../../outside", content: []byte("x")}},
		{name: "symlink", file: syntheticArchiveFile{path: "package/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
		{name: "hard link", file: syntheticArchiveFile{path: "package/link", typeflag: tar.TypeLink, linkname: "package/file"}},
		{name: "device", file: syntheticArchiveFile{path: "package/device", typeflag: tar.TypeChar}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{tt.file})
			_, err := Verify(context.Background(), Options{Artifact: artifact})
			if !errors.Is(err, ErrUnsafeArchive) {
				t.Fatalf("Verify error = %v, want %v", err, ErrUnsafeArchive)
			}
		})
	}
}

func TestVerifyEnforcesArchiveLimits(t *testing.T) {
	t.Parallel()

	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/a", content: []byte("12345")},
		{path: "package/b", content: []byte("67890")},
	})
	tests := []struct {
		name   string
		limits Limits
	}{
		{name: "files", limits: Limits{MaxDownloadBytes: 1 << 20, MaxExpandedBytes: 1 << 20, MaxFileBytes: 1 << 20, MaxFiles: 1}},
		{name: "file bytes", limits: Limits{MaxDownloadBytes: 1 << 20, MaxExpandedBytes: 1 << 20, MaxFileBytes: 4, MaxFiles: 10}},
		{name: "expanded bytes", limits: Limits{MaxDownloadBytes: 1 << 20, MaxExpandedBytes: 9, MaxFileBytes: 8, MaxFiles: 10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), Options{Artifact: artifact, Limits: tt.limits})
			if !errors.Is(err, ErrUnsafeArchive) {
				t.Fatalf("Verify error = %v, want %v", err, ErrUnsafeArchive)
			}
		})
	}
}

type syntheticArchiveFile struct {
	path     string
	content  []byte
	mode     int64
	typeflag byte
	linkname string
}

func writeSyntheticTarGz(t *testing.T, files []syntheticArchiveFile) string {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		mode := file.mode
		if mode == 0 {
			mode = 0o644
		}
		typeflag := file.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name: file.path, Mode: mode, Size: int64(len(file.content)),
			Typeflag: typeflag, Linkname: file.linkname,
		}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tw.Write(file.content); err != nil {
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
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func reportHasFinding(report Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
