package artifactverify

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const (
	SourceDivergenceID = analyze.ArtifactSourceDivergenceID
	PartialBuildID     = analyze.ArtifactPartialBuildID
)

func inspectSource(ctx context.Context, input string, limits Limits, client *http.Client) (archiveReport, error) {
	input = strings.TrimSpace(input)
	parsed, err := url.Parse(input)
	if err != nil {
		return archiveReport{}, fmt.Errorf("parse source input: %w", err)
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		data, err := readInput(ctx, input, limits.MaxDownloadBytes, client)
		if err != nil {
			return archiveReport{}, fmt.Errorf("read source archive: %w", err)
		}
		return inspectArchive(data, input, limits)
	}
	if parsed.Scheme != "" {
		return archiveReport{}, fmt.Errorf("unsupported source URL scheme %q", parsed.Scheme)
	}
	info, err := os.Lstat(input)
	if err != nil {
		return archiveReport{}, fmt.Errorf("inspect source: %w", err)
	}
	if info.IsDir() {
		return inspectSourceDirectory(input, limits)
	}
	if !info.Mode().IsRegular() {
		return archiveReport{}, fmt.Errorf("%w: source must be a regular file or directory", ErrUnsafeArchive)
	}
	data, err := readInput(ctx, input, limits.MaxDownloadBytes, client)
	if err != nil {
		return archiveReport{}, fmt.Errorf("read source archive: %w", err)
	}
	return inspectArchive(data, input, limits)
}

func inspectSourceDirectory(root string, limits Limits) (archiveReport, error) {
	report := archiveReport{format: "directory"}
	slog.Debug("inspecting bounded source directory", "root", root)
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return archiveReport{}, fmt.Errorf("open source root: %w", err)
	}
	defer rootDir.Close()
	err = filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == root {
			return nil
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return unsafeEntry(filePath, "source tree contains a symbolic link")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return unsafeEntry(filePath, "source tree member is not a regular file")
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if info.Size() < 0 || info.Size() > limits.MaxFileBytes {
			return unsafeEntry(relative, "source file exceeds per-file limit")
		}
		if err := addFileBudget(&report, relative, info.Size(), limits); err != nil {
			return err
		}
		file, err := rootDir.Open(filepath.FromSlash(relative))
		if err != nil {
			return err
		}
		content, readErr := readBounded(file, limits.MaxFileBytes)
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		report.files = append(report.files, makeFileRecord(relative, int64(info.Mode().Perm()), content))
		return nil
	})
	if err != nil {
		return archiveReport{}, fmt.Errorf("inspect source directory: %w", err)
	}
	return report, nil
}

func compareSource(artifactFiles, sourceFiles []FileRecord, artifactBytes, sourceBytes int64) []analyze.Finding {
	artifactMap := normalizedFileMap(artifactFiles)
	sourceMap := normalizedFileMap(sourceFiles)
	artifactOnly := make([]string, 0)
	sourceOnly := make([]string, 0)
	changed := make([]string, 0)
	for filePath, artifact := range artifactMap {
		if comparisonIgnored(filePath) {
			continue
		}
		source, ok := sourceMap[filePath]
		if !ok {
			artifactOnly = append(artifactOnly, filePath)
			continue
		}
		if artifact.SHA256 != source.SHA256 {
			changed = append(changed, filePath)
		}
	}
	for filePath := range sourceMap {
		if comparisonIgnored(filePath) {
			continue
		}
		if _, ok := artifactMap[filePath]; !ok {
			sourceOnly = append(sourceOnly, filePath)
		}
	}
	sort.Strings(artifactOnly)
	sort.Strings(sourceOnly)
	sort.Strings(changed)

	findings := make([]analyze.Finding, 0, 2)
	if len(artifactOnly) > 0 || len(changed) > 0 {
		findings = append(findings, packageFinding(
			SourceDivergenceID, analyze.SeverityHigh,
			"Published artifact diverges from reviewed source",
			"The package contains files absent from reviewed source or different bytes at a matching source path.",
			fmt.Sprintf("artifact_only=%s changed=%s source_only=%s",
				boundedPathList(artifactOnly), boundedPathList(changed), boundedPathList(sourceOnly)), "",
		))
	}
	if isPartialBuild(len(artifactMap), len(sourceMap), artifactBytes, sourceBytes) {
		findings = append(findings, packageFinding(
			PartialBuildID, analyze.SeverityMedium,
			"Published artifact appears to be a partial build",
			"The artifact has substantially fewer files or bytes than reviewed source, which can indicate an incomplete or selectively published build.",
			fmt.Sprintf("artifact_files=%d source_files=%d artifact_bytes=%d source_bytes=%d",
				len(artifactMap), len(sourceMap), artifactBytes, sourceBytes), "",
		))
	}
	return findings
}

func normalizedFileMap(files []FileRecord) map[string]FileRecord {
	root := commonArchiveRoot(files)
	normalized := make(map[string]FileRecord, len(files))
	for _, file := range files {
		filePath := strings.TrimPrefix(file.Path, "./")
		if root != "" {
			filePath = strings.TrimPrefix(filePath, root+"/")
		}
		normalized[filePath] = file
	}
	return normalized
}

func commonArchiveRoot(files []FileRecord) string {
	var root string
	for _, file := range files {
		parts := strings.SplitN(strings.TrimPrefix(file.Path, "./"), "/", 2)
		if len(parts) != 2 {
			return ""
		}
		if root == "" {
			root = parts[0]
		} else if root != parts[0] {
			return ""
		}
	}
	return root
}

func comparisonIgnored(filePath string) bool {
	lower := strings.ToLower(filePath)
	for _, part := range strings.Split(lower, "/") {
		if strings.HasSuffix(part, ".dist-info") || strings.HasSuffix(part, ".egg-info") {
			return true
		}
	}
	return path.Base(lower) == "metadata.gz"
}

func boundedPathList(paths []string) string {
	const maxPaths = 5
	if len(paths) > maxPaths {
		return stringutil.TruncateEvidence(strings.Join(paths[:maxPaths], ",")+fmt.Sprintf(",...(+%d)", len(paths)-maxPaths), 300)
	}
	return stringutil.TruncateEvidence(strings.Join(paths, ","), 300)
}

func isPartialBuild(artifactFiles, sourceFiles int, artifactBytes, sourceBytes int64) bool {
	if sourceFiles < 5 || sourceBytes <= 0 {
		return false
	}
	return artifactFiles*2 < sourceFiles || artifactBytes < sourceBytes/4
}
