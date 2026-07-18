package enumerate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// EnumerateLocal scans local filesystem paths for .gitlab-ci.yml files and
// runs the full analysis pipeline without any GitLab API calls. Each path
// may be a directory (walked recursively for .gitlab-ci.yml files) or a
// direct path to a CI YAML file.
func EnumerateLocal(ctx context.Context, paths []string, opts Options) ([]Result, error) {
	ciFiles, err := collectCIFiles(paths)
	if err != nil {
		return nil, err
	}
	slog.Info("local enumerate", "ci_files", len(ciFiles))

	var results []Result
	for _, cf := range ciFiles {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		r := scanLocalFile(cf, opts)
		if r != nil {
			results = append(results, *r)
		}
	}
	return results, nil
}

func collectCIFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d os.DirEntry, werr error) error {
			if werr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() == ".gitlab-ci.yml" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", p, err)
		}
	}
	return files, nil
}

func scanLocalFile(path string, opts Options) *Result {
	start := time.Now()
	f, err := os.Open(path)
	if err != nil {
		slog.Warn("cannot open CI file", "path", path, "error", err)
		return nil
	}
	defer f.Close()

	doc, err := pipeline.Parse(f)
	if err != nil {
		slog.Warn("cannot parse CI file", "path", path, "error", err)
		return &Result{
			ProjectPathWithNS: path,
			Error:             fmt.Sprintf("parse error: %v", err),
			DurationMS:        time.Since(start).Milliseconds(),
		}
	}

	projPath := deriveProjectPath(path)
	var summary strings.Builder
	fmt.Fprintf(&summary, "%d jobs", len(doc.Jobs))
	if len(doc.Stages) > 0 {
		fmt.Fprintf(&summary, ", %d stages", len(doc.Stages))
	}

	var aopts []analyze.Option
	if opts.Redact {
		aopts = append(aopts, analyze.WithRedactedSecrets())
	}
	findings, aerr := analyze.Run(doc, aopts...)
	if aerr != nil {
		slog.Warn("analysis error", "path", path, "error", aerr)
	}

	return &Result{
		ProjectPathWithNS: projPath,
		HasCIPipeline:     true,
		CISummary:         summary.String(),
		Findings:          findings,
		DurationMS:        time.Since(start).Milliseconds(),
	}
}

func deriveProjectPath(ciPath string) string {
	dir := filepath.Dir(ciPath)
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
}
