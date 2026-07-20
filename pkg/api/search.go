package api

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pathutil"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// searchProjects is the default implementation of searcherFn.
// It discovers GitLab projects via the Projects API, then applies per-project
// filters (topic, language, path-exists, path-pattern, code-content) in sequence.
//
//nolint:gocognit
func searchProjects(ctx context.Context, cl *gitlabx.Client, opts searchProjectsOptions) ([]searchProjectResult, error) {
	// --- Phase 1: List projects via API -----------------------------------
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	maxPages := opts.MaxPages
	if maxPages < 0 {
		maxPages = 1
	}

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
	if opts.Archived {
		listOpts.Archived = new(true)
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
		}
		listOpts.Visibility = &vv
	}

	var projects []*gitlab.Project
	var pagesFetched int64
	for {
		projs, resp, err := cl.GL.Projects.ListProjects(listOpts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		projects = append(projects, projs...)
		pagesFetched++
		if (maxPages > 0 && pagesFetched >= maxPages) || resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	// --- Phase 2: Per-project filters ------------------------------------

	// Topic filter (client-side, no API call)
	if t := strings.TrimSpace(opts.Topic); t != "" {
		wantTopics := parseCSV(t)
		if len(wantTopics) > 0 {
			var filtered []*gitlab.Project
			for _, p := range projects {
				for _, pt := range p.Topics {
					if _, ok := wantTopics[strings.ToLower(strings.TrimSpace(pt))]; ok {
						filtered = append(filtered, p)
						break
					}
				}
			}
			projects = filtered
		}
	}

	// Language filter (per-project API call)
	if l := strings.TrimSpace(opts.Language); l != "" && len(projects) > 0 {
		wantLangs := parseCSV(l)
		if len(wantLangs) > 0 {
			projects = filterConcurrent(ctx, cl, projects, concFor(opts.Concurrency), func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool {
				langs, err := cl.GetProjectLanguages(ctx, p.ID)
				if err != nil {
					return false
				}
				for k := range langs {
					if _, ok := wantLangs[strings.ToLower(strings.TrimSpace(k))]; ok {
						return true
					}
				}
				return false
			})
		}
	}

	// Path-exists filter (exact file existence)
	if pe := strings.TrimSpace(opts.PathExists); pe != "" && len(projects) > 0 {
		projects = filterConcurrent(ctx, cl, projects, concFor(opts.Concurrency), func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool {
			ref := refFor(opts.Ref, p)
			if ref == "" {
				return false
			}
			_, resp, err := cl.GL.RepositoryFiles.GetFile(p.ID, strings.TrimLeft(pe, "/"), &gitlab.GetFileOptions{Ref: new(ref)}, gitlab.WithContext(ctx))
			return err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300
		})
	}

	// Path-pattern filter (glob match against repo tree)
	if pp := strings.TrimSpace(opts.PathPattern); pp != "" && len(projects) > 0 {
		rgx, err := pathutil.GlobToRegex(pp)
		if err != nil {
			return nil, err
		}
		pathPerPage := opts.PathPerPage
		if pathPerPage <= 0 {
			pathPerPage = 100
		}
		pathMaxPages := opts.PathMaxPages
		if pathMaxPages <= 0 {
			pathMaxPages = 10
		}
		projects = filterConcurrent(ctx, cl, projects, concFor(opts.Concurrency), func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool {
			ref := refFor(opts.Ref, p)
			paths, err := cl.ListRepoTreePaths(ctx, p.ID, ref, true, pathPerPage, pathMaxPages)
			if err != nil {
				return false
			}
			return slices.ContainsFunc(paths, rgx.MatchString)
		})
	}

	// Code-content filter (per-project code search)
	if cc := strings.TrimSpace(opts.CodeContent); cc != "" && len(projects) > 0 {
		codePerPage := opts.CodePerPage
		if codePerPage <= 0 {
			codePerPage = 20
		}
		codeMaxPages := opts.CodeMaxPages
		if codeMaxPages <= 0 {
			codeMaxPages = 1
		}
		projects = filterConcurrent(ctx, cl, projects, concFor(opts.Concurrency), func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool {
			ref := refFor(opts.Ref, p)
			matches, err := cl.CodeSearch(ctx, p.ID, cc, ref, codePerPage, codeMaxPages)
			return err == nil && len(matches) > 0
		})
	}

	// --- Phase 3: Convert to response types ------------------------------
	results := make([]searchProjectResult, 0, len(projects))
	for _, p := range projects {
		results = append(results, searchProjectResult{
			ID:                p.ID,
			PathWithNamespace: p.PathWithNamespace,
			WebURL:            p.WebURL,
			Visibility:        string(p.Visibility),
			DefaultBranch:     p.DefaultBranch,
			StarCount:         p.StarCount,
			Archived:          p.Archived,
		})
	}
	return results, nil
}

// parseCSV splits a comma-separated string into a lowercase set.
func parseCSV(s string) map[string]struct{} {
	m := make(map[string]struct{})
	for v := range strings.SplitSeq(s, ",") {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			m[v] = struct{}{}
		}
	}
	return m
}

// refFor returns the git ref to use, preferring the explicit ref over the project's default branch.
func refFor(explicit string, p *gitlab.Project) string {
	if r := strings.TrimSpace(explicit); r != "" {
		return r
	}
	return p.DefaultBranch
}

// concFor returns a bounded concurrency value.
func concFor(c int) int {
	if c <= 0 {
		c = runtime.GOMAXPROCS(0)
	}
	if c > 64 {
		c = 64
	}
	return c
}

// filterFn is a per-project predicate used by filterConcurrent.
type filterFn func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool

// filterConcurrent runs fn against each project concurrently and returns those where fn returns true.
func filterConcurrent(ctx context.Context, cl *gitlabx.Client, projects []*gitlab.Project, conc int, fn filterFn) []*gitlab.Project {
	type job struct{ p *gitlab.Project }
	type result struct {
		p  *gitlab.Project
		ok bool
	}
	in := make(chan job)
	out := make(chan result)
	var wg sync.WaitGroup
	wg.Add(conc)
	for range conc {
		go func() {
			defer wg.Done()
			for j := range in {
				ok := func() (res bool) {
					defer func() {
						if r := recover(); r != nil {
							res = false
						}
					}()
					return fn(ctx, cl, j.p)
				}()
				out <- result{p: j.p, ok: ok}
			}
		}()
	}
	go func() {
		defer close(in)
		for _, p := range projects {
			select {
			case in <- job{p: p}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	var filtered []*gitlab.Project
	for r := range out {
		if r.ok {
			filtered = append(filtered, r.p)
		}
	}
	return filtered
}
