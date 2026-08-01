package depscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type boundedArchiveWriter struct {
	writer    io.Writer
	remaining int64
	exceeded  bool
}

func (w *boundedArchiveWriter) Write(p []byte) (int, error) {
	if int64(len(p)) <= w.remaining {
		n, err := w.writer.Write(p)
		w.remaining -= int64(n)
		return n, err
	}
	w.exceeded = true
	if w.remaining <= 0 {
		return 0, ErrArchiveTooLarge
	}
	allowed := int(w.remaining)
	n, err := w.writer.Write(p[:allowed])
	w.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	return n, ErrArchiveTooLarge
}

// ScanGitLabProject downloads a bounded GitLab repository archive, extracts
// only regular files and directories into a confined temporary root, and
// audits dependency metadata. It never invokes a package manager or executes
// repository/package content.
func (s *Scanner) ScanGitLabProject(
	ctx context.Context,
	client *gitlabx.Client,
	projectID int64,
	ref string,
) (Report, error) {
	if s == nil || s.auditor == nil {
		return Report{}, errors.New("scan GitLab dependencies: nil depx scanner")
	}
	if client == nil || client.GL == nil {
		return Report{}, errors.New("scan GitLab dependencies: nil GitLab client")
	}
	if projectID <= 0 {
		return Report{}, fmt.Errorf("scan GitLab dependencies: invalid project ID %d", projectID)
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Report{}, errors.New("scan GitLab dependencies: empty ref")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	limits := s.archiveLimits.withDefaults()
	tempRoot, err := os.MkdirTemp("", "gogatoz-depx-")
	if err != nil {
		return Report{}, fmt.Errorf("create dependency scan workspace: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tempRoot); removeErr != nil {
			slog.Warn("remove dependency scan workspace", "path", tempRoot, "error", removeErr)
		}
	}()

	archivePath := filepath.Join(tempRoot, "repository.tar.gz")
	archiveFile, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Report{}, fmt.Errorf("create bounded repository archive: %w", err)
	}
	bounded := &boundedArchiveWriter{writer: archiveFile, remaining: limits.MaxArchiveBytes}
	archiveFormat := "tar.gz"
	_, streamErr := client.GL.Repositories.StreamArchive(projectID, bounded, &gitlab.ArchiveOptions{
		Format: &archiveFormat,
		SHA:    &ref,
	}, gitlab.WithContext(ctx))
	closeErr := archiveFile.Close()
	if bounded.exceeded || errors.Is(streamErr, ErrArchiveTooLarge) {
		return Report{}, fmt.Errorf("download repository archive: %w", ErrArchiveTooLarge)
	}
	if streamErr != nil {
		return Report{}, fmt.Errorf("download GitLab repository archive: %w", streamErr)
	}
	if closeErr != nil {
		return Report{}, fmt.Errorf("close repository archive: %w", closeErr)
	}

	extractionRoot := filepath.Join(tempRoot, "repository")
	if err := os.Mkdir(extractionRoot, 0o700); err != nil {
		return Report{}, fmt.Errorf("create archive extraction directory: %w", err)
	}
	archiveFile, err = os.Open(archivePath)
	if err != nil {
		return Report{}, fmt.Errorf("open downloaded repository archive: %w", err)
	}
	extractErr := extractTarGz(archiveFile, extractionRoot, limits)
	closeErr = archiveFile.Close()
	if extractErr != nil {
		return Report{}, fmt.Errorf("extract GitLab repository archive: %w", extractErr)
	}
	if closeErr != nil {
		return Report{}, fmt.Errorf("close downloaded repository archive: %w", closeErr)
	}
	auditPaths, err := gitLabDependencyAuditPaths(extractionRoot)
	if err != nil {
		return Report{}, fmt.Errorf("discover GitLab repository SBOMs: %w", err)
	}

	slog.Info("auditing GitLab repository dependency metadata", "project_id", projectID, "ref", ref,
		"paths", len(auditPaths))
	report, err := s.Scan(ctx, auditPaths)
	if err != nil {
		return Report{}, fmt.Errorf("scan GitLab repository dependency metadata: %w", err)
	}
	normalizeRepositoryLocations(&report, extractionRoot)
	return report, nil
}

// gitLabDependencyAuditPaths supplements depx's recursive lockfile discovery
// with explicit SBOM paths. depx v0.1.1 accepts these names when provided as
// files but its directory discovery currently enumerates lockfiles only.
func gitLabDependencyAuditPaths(extractionRoot string) ([]string, error) {
	paths := []string{extractionRoot}
	err := filepath.WalkDir(extractionRoot, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !isDepxSBOMFilename(entry.Name()) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			paths = append(paths, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths[1:])
	return paths, nil
}

// isDepxSBOMFilename mirrors the native depx v0.1.1 SBOM filename contract.
// depx remains responsible for parsing the file and auditing its dependencies.
func isDepxSBOMFilename(name string) bool {
	base := strings.ToLower(strings.TrimSpace(name))
	if base == "bom.json" || base == "bom.xml" {
		return true
	}
	for _, suffix := range []string{
		".cdx.json", ".cdx.xml",
		".cyclonedx.json", ".cyclonedx.xml",
		".spdx.json", ".spdx", ".spdx.yml", ".spdx.rdf", ".spdx.rdf.xml",
	} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func normalizeRepositoryLocations(report *Report, extractionRoot string) {
	if report == nil {
		return
	}
	for i := range report.Paths {
		if filepath.Clean(report.Paths[i]) == filepath.Clean(extractionRoot) {
			report.Paths[i] = "."
			continue
		}
		report.Paths[i] = repositoryRelativePath(report.Paths[i], extractionRoot)
	}
	for i := range report.Lockfiles {
		report.Lockfiles[i].Path = repositoryRelativePath(report.Lockfiles[i].Path, extractionRoot)
	}
	for i := range report.Findings {
		oldSource := report.Findings[i].SourceFile
		newSource := repositoryRelativePath(oldSource, extractionRoot)
		report.Findings[i].SourceFile = newSource
		if oldSource != "" && oldSource != newSource {
			report.Findings[i].Evidence = strings.ReplaceAll(report.Findings[i].Evidence, oldSource, newSource)
		}
	}
	if report.SBOMPath != "" {
		report.SBOMPath = repositoryRelativePath(report.SBOMPath, extractionRoot)
	}
}

func repositoryRelativePath(sourcePath, extractionRoot string) string {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return ""
	}
	relative, err := filepath.Rel(extractionRoot, sourcePath)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return filepath.ToSlash(filepath.Base(sourcePath))
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) > 1 {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}
