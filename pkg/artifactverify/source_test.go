package artifactverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyComparesArtifactWithReviewedSource(t *testing.T) {
	t.Parallel()

	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`)},
		{path: "package/dist/index.js", content: []byte("export const fixture = 'artifact';\n")},
	})
	source := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "project-v1.2.3/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`)},
		{path: "project-v1.2.3/src/index.js", content: []byte("export const fixture = 'source';\n")},
	})

	report, err := Verify(context.Background(), Options{Artifact: artifact, Source: source})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.SourceFiles != 2 || report.SourceBytes == 0 {
		t.Fatalf("source report = %+v", report)
	}
	if !reportHasFinding(report, SourceDivergenceID) {
		t.Fatalf("missing %s: %+v", SourceDivergenceID, report.Findings)
	}
}

func TestVerifyDetectsPartialBuildByFileCountOrSize(t *testing.T) {
	t.Parallel()

	artifact := writeSyntheticTarGz(t, []syntheticArchiveFile{
		{path: "package/package.json", content: []byte(`{"name":"gogatoz-fixture","version":"1.2.3"}`)},
		{path: "package/index.js", content: []byte("export {};\n")},
	})
	sourceFiles := make([]syntheticArchiveFile, 0, 12)
	for i := 0; i < 12; i++ {
		sourceFiles = append(sourceFiles, syntheticArchiveFile{
			path:    "project-v1.2.3/src/file-" + string(rune('a'+i)) + ".js",
			content: []byte("export const syntheticFixtureValue = '012345678901234567890123456789';\n"),
		})
	}
	source := writeSyntheticTarGz(t, sourceFiles)

	report, err := Verify(context.Background(), Options{Artifact: artifact, Source: source})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reportHasFinding(report, PartialBuildID) {
		t.Fatalf("missing %s: %+v", PartialBuildID, report.Findings)
	}
}

func TestInspectSourceRejectsSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "regular.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("regular.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	_, err := inspectSource(context.Background(), root, DefaultLimits(), nil)
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Fatalf("inspectSource error = %v, want %v", err, ErrUnsafeArchive)
	}
}

func TestInspectSourceDirectoryCollectsRegularFilesAndSkipsGit(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "fixture.go"), []byte("package fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := inspectSource(context.Background(), root, DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("inspectSource: %v", err)
	}
	if len(report.files) != 1 || report.files[0].Path != "src/fixture.go" {
		t.Fatalf("source directory report = %+v", report)
	}
}
