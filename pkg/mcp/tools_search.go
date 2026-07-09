package mcpserver

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// searchTool is the MCP tool definition for project search.
var searchTool = &mcp.Tool{
	Name: "search_projects",
	Description: `Search GitLab for projects matching filters. Returns project IDs, paths, URLs, and metadata.

Supports query-based search (name/path/description), plus optional filters: visibility, topic, language, owned, membership, and path_exists (exact file path check). Results are paginated; increase max_pages for broader discovery.

Use this tool first to discover targets before running enumerate_projects.`,
}

// --- Input / Output types ------------------------------------------------

type searchInput struct {
	Query      string `json:"query"       jsonschema:"Search query matching project name, path, or description"`
	PerPage    int64  `json:"per_page"    jsonschema:"Results per page (default 50)"`
	MaxPages   int64  `json:"max_pages"   jsonschema:"Maximum pages to fetch (default 1, 0 means unlimited)"`
	Owned      bool   `json:"owned"       jsonschema:"Only projects owned by authenticated user"`
	Membership bool   `json:"membership"  jsonschema:"Only projects the user is a member of"`
	Visibility string `json:"visibility"  jsonschema:"Filter by visibility: public, internal, or private"`
	Topic      string `json:"topic"       jsonschema:"Comma-separated topic/tag filter (matches any)"`
	Language   string `json:"language"    jsonschema:"Comma-separated language filter (matches any)"`
	PathExists string `json:"path_exists" jsonschema:"Keep only projects containing this exact file path"`
}

type searchProjectOut struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	Visibility        string `json:"visibility"`
	DefaultBranch     string `json:"default_branch"`
	StarCount         int64  `json:"star_count"`
}

type searchOutput struct {
	Projects []searchProjectOut `json:"projects"`
	Total    int                `json:"total"`
}

// --- Handler -------------------------------------------------------------

func (s *Server) handleSearchProjects(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input searchInput,
) (*mcp.CallToolResult, searchOutput, error) {
	if v := strings.TrimSpace(input.Visibility); v != "" {
		switch strings.ToLower(v) {
		case "public", "internal", "private": //nolint:goconst // well-known GitLab visibility values
		default:
			return nil, searchOutput{}, fmt.Errorf("invalid visibility %q: use public, internal, or private", v)
		}
	}

	projects, err := listProjects(ctx, s.client, input)
	if err != nil {
		return nil, searchOutput{}, fmt.Errorf("search failed: %w", err)
	}

	// Per-project filters
	projects = applyTopicFilter(projects, input.Topic)
	projects, err = applyLanguageFilter(ctx, s.client, projects, input.Language)
	if err != nil {
		return nil, searchOutput{}, err
	}
	projects = applyPathExistsFilter(ctx, s.client, projects, input.PathExists)

	out := searchOutput{
		Projects: make([]searchProjectOut, len(projects)),
		Total:    len(projects),
	}
	for i, p := range projects {
		out.Projects[i] = searchProjectOut{
			ID:                p.ID,
			PathWithNamespace: p.PathWithNamespace,
			WebURL:            p.WebURL,
			Visibility:        string(p.Visibility),
			DefaultBranch:     p.DefaultBranch,
			StarCount:         p.StarCount,
		}
	}
	s.persistSearch(out)
	return nil, out, nil
}

func (s *Server) persistSearch(out searchOutput) {
	if s.store == nil {
		return
	}
	now := time.Now()
	session := &store.ScanSession{
		GitLabURL:   s.gitlabURL,
		StartedAt:   now,
		FinishedAt:  &now,
		Status:      "completed",
		SearchTotal: out.Total,
	}
	if err := s.store.CreateSession(session); err != nil {
		return
	}
	srs := make([]store.SearchResult, len(out.Projects))
	for i, p := range out.Projects {
		srs[i] = store.SearchResult{
			GitLabProjectID:   p.ID,
			PathWithNamespace: p.PathWithNamespace,
			WebURL:            p.WebURL,
			Visibility:        p.Visibility,
			DefaultBranch:     p.DefaultBranch,
			StarCount:         p.StarCount,
		}
	}
	_ = s.store.SaveSearchResults(session.ID, srs)
}

// --- Search implementation -----------------------------------------------

func listProjects(ctx context.Context, cl *gitlabx.Client, input searchInput) ([]*gitlab.Project, error) {
	perPage := input.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 100 {
		perPage = 100
	}
	maxPages := input.MaxPages
	if maxPages <= 0 {
		maxPages = 1
	}

	listOpts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{Page: 1, PerPage: perPage},
	}
	if q := strings.TrimSpace(input.Query); q != "" {
		listOpts.Search = new(q)
	}
	if input.Owned {
		listOpts.Owned = new(true)
	}
	if input.Membership {
		listOpts.Membership = new(true)
	}
	if v := strings.ToLower(strings.TrimSpace(input.Visibility)); v != "" {
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
	return projects, nil
}

// --- Per-project filters -------------------------------------------------

func applyTopicFilter(projects []*gitlab.Project, topic string) []*gitlab.Project {
	t := strings.TrimSpace(topic)
	if t == "" {
		return projects
	}
	want := parseCSV(t)
	if len(want) == 0 {
		return projects
	}
	var filtered []*gitlab.Project
	for _, p := range projects {
		for _, pt := range p.Topics {
			if _, ok := want[strings.ToLower(strings.TrimSpace(pt))]; ok {
				filtered = append(filtered, p)
				break
			}
		}
	}
	return filtered
}

func applyLanguageFilter(ctx context.Context, cl *gitlabx.Client, projects []*gitlab.Project, language string) ([]*gitlab.Project, error) {
	l := strings.TrimSpace(language)
	if l == "" || len(projects) == 0 {
		return projects, nil
	}
	want := parseCSV(l)
	if len(want) == 0 {
		return projects, nil
	}
	return filterConcurrent(ctx, cl, projects, func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool {
		langs, err := cl.GetProjectLanguages(ctx, p.ID)
		if err != nil {
			return false
		}
		for k := range langs {
			if _, ok := want[strings.ToLower(strings.TrimSpace(k))]; ok {
				return true
			}
		}
		return false
	}), nil
}

func applyPathExistsFilter(ctx context.Context, cl *gitlabx.Client, projects []*gitlab.Project, pathExists string) []*gitlab.Project {
	pe := strings.TrimSpace(pathExists)
	if pe == "" || len(projects) == 0 {
		return projects
	}
	return filterConcurrent(ctx, cl, projects, func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool {
		ref := p.DefaultBranch
		if ref == "" {
			return false
		}
		_, resp, err := cl.GL.RepositoryFiles.GetFile(p.ID, strings.TrimLeft(pe, "/"), &gitlab.GetFileOptions{Ref: new(ref)}, gitlab.WithContext(ctx))
		return err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300
	})
}

// --- Helpers -------------------------------------------------------------

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

type filterFn func(ctx context.Context, cl *gitlabx.Client, p *gitlab.Project) bool

func filterConcurrent(ctx context.Context, cl *gitlabx.Client, projects []*gitlab.Project, fn filterFn) []*gitlab.Project {
	conc := min(runtime.GOMAXPROCS(0), 64)

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
				out <- result{p: j.p, ok: fn(ctx, cl, j.p)}
			}
		}()
	}
	go func() {
		for _, p := range projects {
			in <- job{p: p}
		}
		close(in)
	}()
	var filtered []*gitlab.Project
	for range len(projects) {
		r := <-out
		if r.ok {
			filtered = append(filtered, r.p)
		}
	}
	wg.Wait()
	return filtered
}
