package secretscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Options controls secretscan behavior.
type Options struct {
	OutputDir    string
	Scanners     string // "auto" or comma-separated
	Concurrency  int
	CloneDepth   int
	DiscardRepos bool
	Redact       bool

	// Project discovery filters (used when not in scan-dir mode)
	Query      string
	Visibility string
	PerPage    int64
	MaxPages   int64
	Owned      bool
	Membership bool
	Topic      string
	Language   string

	// Scan existing directory instead of cloning
	ScanDir string

	// Progress, if set, is called once per completed project result.
	Progress func(ScanResult)
}

// projectInfo holds the minimal project metadata needed for cloning and scanning.
type projectInfo struct {
	ID                int64
	PathWithNamespace string
	WebURL            string
	HTTPURLToRepo     string
}

// Run discovers GitLab projects, clones them, scans for secrets, and returns results.
// If opts.ScanDir is set, it skips discovery and cloning, scanning existing repos instead.
func Run(ctx context.Context, cl *gitlabx.Client, token string, opts Options) ([]ScanResult, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.CloneDepth <= 0 {
		opts.CloneDepth = 1
	}

	scanners, err := ParseScanners(opts.Scanners)
	if err != nil {
		return nil, err
	}

	// Determine projects to scan
	var projects []projectInfo
	if opts.ScanDir != "" {
		repos, err := DiscoverRepos(opts.ScanDir)
		if err != nil {
			return nil, fmt.Errorf("discover repos: %w", err)
		}
		if len(repos) == 0 {
			return nil, fmt.Errorf("no git repositories found under %s", opts.ScanDir)
		}
		for _, r := range repos {
			rel, _ := filepath.Rel(opts.ScanDir, r)
			projects = append(projects, projectInfo{
				PathWithNamespace: filepath.ToSlash(rel),
			})
		}
	} else {
		if cl == nil {
			return nil, fmt.Errorf("GitLab client required for project discovery (use --scan-dir for offline scanning)")
		}
		discovered, err := discoverProjects(ctx, cl, opts)
		if err != nil {
			return nil, fmt.Errorf("discover projects: %w", err)
		}
		if len(discovered) == 0 {
			return nil, fmt.Errorf("no projects found matching filters")
		}
		projects = discovered
	}

	// Worker pool
	type job struct {
		project projectInfo
	}

	jobs := make(chan job)
	var mu sync.Mutex
	var results []ScanResult
	var wg sync.WaitGroup

	wg.Add(opts.Concurrency)
	for i := 0; i < opts.Concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := scanOneProject(ctx, j.project, scanners, token, opts)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				if opts.Progress != nil {
					opts.Progress(res)
				}
			}
		}()
	}

	for _, p := range projects {
		select {
		case jobs <- job{project: p}:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

// scanOneProject clones (or uses existing) a single project and runs all scanners.
func scanOneProject(ctx context.Context, proj projectInfo, scanners []*Scanner, token string, opts Options) ScanResult {
	start := time.Now()
	r := ScanResult{
		GitLabProjectID:   proj.ID,
		PathWithNamespace: proj.PathWithNamespace,
		WebURL:            proj.WebURL,
	}

	// Determine repo path
	var repoPath string
	needsClone := opts.ScanDir == ""

	if needsClone {
		repoPath = CloneDestPath(opts.OutputDir, proj.PathWithNamespace)
		r.ClonePath = repoPath

		// Clone the project
		if err := CloneProject(ctx, proj.HTTPURLToRepo, token, repoPath, opts.CloneDepth); err != nil {
			r.Error = fmt.Sprintf("clone: %v", err)
			r.DurationMS = time.Since(start).Milliseconds()
			return r
		}
	} else {
		repoPath = filepath.Join(opts.ScanDir, filepath.FromSlash(proj.PathWithNamespace))
		r.ClonePath = repoPath
	}

	// Run each scanner
	var scannerNames []string
	for _, s := range scanners {
		findings, err := s.Scan(ctx, repoPath)
		if err != nil {
			if r.Error != "" {
				r.Error += "; "
			}
			r.Error += fmt.Sprintf("%s: %v", s.Name, err)
			continue
		}
		r.Findings = append(r.Findings, findings...)
		scannerNames = append(scannerNames, s.Name)
	}
	r.Scanners = scannerNames
	r.FindingsCount = len(r.Findings)

	// Optionally redact secrets
	if opts.Redact {
		r.Findings = RedactFindings(r.Findings)
	}

	// Optionally discard cloned repo
	if needsClone && opts.DiscardRepos && repoPath != "" {
		_ = os.RemoveAll(repoPath)
		r.ClonePath = "" // clear since it's been removed
	}

	r.DurationMS = time.Since(start).Milliseconds()
	return r
}

// discoverProjects fetches projects from the GitLab API with pagination and filters.
func discoverProjects(ctx context.Context, cl *gitlabx.Client, opts Options) ([]projectInfo, error) {
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 100 {
		perPage = 100
	}
	maxPages := opts.MaxPages // 0 = unlimited

	listOpts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{Page: 1, PerPage: perPage},
	}
	if q := strings.TrimSpace(opts.Query); q != "" {
		listOpts.Search = new(q)
	}
	if opts.Owned {
		listOpts.Owned = new(true)
	}
	if opts.Membership {
		listOpts.Membership = new(true)
	}
	if v := strings.ToLower(strings.TrimSpace(opts.Visibility)); v != "" {
		var vv gitlab.VisibilityValue
		switch v {
		case "public":
			vv = gitlab.PublicVisibility
		case "internal":
			vv = gitlab.InternalVisibility
		case "private":
			vv = gitlab.PrivateVisibility
		default:
			return nil, fmt.Errorf("invalid visibility %q: use public, internal, or private", v)
		}
		listOpts.Visibility = &vv
	}

	var projects []projectInfo
	var pagesFetched int64
	for {
		projs, resp, err := cl.GL.Projects.ListProjects(listOpts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		for _, p := range projs {
			projects = append(projects, projectInfo{
				ID:                p.ID,
				PathWithNamespace: p.PathWithNamespace,
				WebURL:            p.WebURL,
				HTTPURLToRepo:     p.HTTPURLToRepo,
			})
		}
		pagesFetched++
		if (maxPages > 0 && pagesFetched >= maxPages) || resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	return projects, nil
}
