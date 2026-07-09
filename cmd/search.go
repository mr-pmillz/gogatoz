package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	searchQuery  string
	perPage      int64
	maxPages     int64
	owned        bool
	membership   bool
	visibility   string
	archivedOnly bool
	// Per-command instance override (self-hosted/internal)
	instanceURL string
	pathExists  string
	// Path pattern filtering
	pathPattern  string
	pathRef      string
	pathPerPage  int
	pathMaxPages int
	pathConc     int
	// Code content filtering
	codeContent  string
	codeRef      string
	codePerPage  int
	codeMaxPages int
	codeConc     int
	// Language/topic filtering
	languages string
	topics    string
	langConc  int
	// Output formatting
	format     string // text|json|jsonl (default respects --json)
	outputPath string
)

// searchCmd represents the search command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search GitLab projects using the API",
	Long:  "Search GitLab projects by name/path/description using GitLab's project search and print results.",
	RunE: func(cmd *cobra.Command, args []string) error {

		ctx := context.Background()
		clOpts := []gitlabx.Option{gitlabx.WithRateLimit(rateRPS, rateBurst), gitlabx.WithRetry(retryMax)}
		if ua := userAgent; strings.TrimSpace(ua) != "" {
			clOpts = append(clOpts, gitlabx.WithUserAgent(ua))
		}
		// HTTP pooling/timeouts from global settings
		var idleTO, tlsTO, expectTO, reqTO time.Duration
		if s := strings.TrimSpace(httpIdleTimeout); s != "" {
			if d, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("invalid --http-idle-timeout: %w", err)
			} else {
				idleTO = d
			}
		}
		if s := strings.TrimSpace(httpTLSTimeout); s != "" {
			if d, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("invalid --http-tls-timeout: %w", err)
			} else {
				tlsTO = d
			}
		}
		if s := strings.TrimSpace(httpExpectTimeout); s != "" {
			if d, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("invalid --http-expect-timeout: %w", err)
			} else {
				expectTO = d
			}
		}
		if s := strings.TrimSpace(httpRequestTimeout); s != "" {
			if d, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("invalid --http-req-timeout: %w", err)
			} else {
				reqTO = d
			}
		}
		if httpMaxIdle > 0 || httpMaxIdlePerHost > 0 {
			clOpts = append(clOpts, gitlabx.WithHTTPPool(httpMaxIdle, httpMaxIdlePerHost))
		}
		if idleTO > 0 || tlsTO > 0 || expectTO > 0 || reqTO > 0 {
			clOpts = append(clOpts, gitlabx.WithHTTPTimeouts(idleTO, tlsTO, expectTO, reqTO))
		}
		// TLS options for internal/self-hosted GitLab
		if insecureSkipTLS {
			clOpts = append(clOpts, gitlabx.WithInsecureTLS(true))
		}
		if p := strings.TrimSpace(caCertPath); p != "" {
			pem, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("read --ca-cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("--ca-cert: no valid PEM certificates found")
			}
			clOpts = append(clOpts, gitlabx.WithRootCAs(pool))
		}
		clOpts = appendSOCKS5Option(clOpts)
		// Allow per-command override for internal/self-hosted instances
		base := strings.TrimSpace(gitlabURL)
		if inst := strings.TrimSpace(instanceURL); inst != "" {
			if base != "" && inst != base {
				_, _ = fmt.Fprintln(os.Stderr, "warning: --instance is deprecated; prefer --gitlab-url. Using --instance value for this command.")
			}
			base = inst
		}
		client, err := gitlabx.New(base, token, clOpts...)
		if err != nil {
			return err
		}
		// small ping to validate
		if verbose {
			if u, _, err := client.Ping(ctx); err == nil {
				_, err = fmt.Fprintf(os.Stderr, "Authenticated as %s\n", u.Username)
				if err != nil {
					return err
				}
			}
		}

		opts := &gitlab.ListProjectsOptions{
			ListOptions: gitlab.ListOptions{Page: 1, PerPage: perPage},
		}
		if strings.TrimSpace(searchQuery) != "" {
			opts.Search = new(searchQuery)
		}

		// Apply simple filters
		if owned {
			opts.Owned = new(true)
		}
		if membership {
			opts.Membership = new(true)
		}
		if archivedOnly {
			opts.Archived = new(true)
		}
		if v := strings.ToLower(strings.TrimSpace(visibility)); v != "" {
			var vv gitlab.VisibilityValue
			switch v {
			case "public":
				vv = gitlab.PublicVisibility
			case "internal":
				vv = gitlab.InternalVisibility
			case "private":
				vv = gitlab.PrivateVisibility
			default:
				return fmt.Errorf("invalid --visibility: %s (use public|internal|private)", visibility)
			}
			opts.Visibility = &vv
		}

		var all []map[string]any
		var projObjs []*gitlab.Project
		var pagesFetched int64
		for {
			projects, resp, err := client.GL.Projects.ListProjects(opts, gitlab.WithContext(ctx))
			if err != nil {
				return err
			}
			for _, p := range projects {
				projObjs = append(projObjs, p)
				row := map[string]any{
					"id":                  p.ID,
					"path_with_namespace": p.PathWithNamespace,
					"http_url_to_repo":    p.HTTPURLToRepo,
					"web_url":             p.WebURL,
					"visibility":          p.Visibility,
					"last_activity_at":    p.LastActivityAt,
					"star_count":          p.StarCount,
					"forks_count":         p.ForksCount,
					"default_branch":      p.DefaultBranch,
					"archived":            p.Archived,
					"created_at":          p.CreatedAt,
					"readme_url":          p.ReadmeURL,
				}
				all = append(all, row)
			}

			pagesFetched++
			// Treat max-pages=0 as unlimited until NextPage==0
			if (maxPages > 0 && pagesFetched >= maxPages) || resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
			// be a little nice
			time.Sleep(50 * time.Millisecond)
		}

		// Optional topic filter (simple contains-any on project topics)
		if strings.TrimSpace(topics) != "" && len(projObjs) > 0 {
			wantTopics := map[string]struct{}{}
			for t := range strings.SplitSeq(topics, ",") {
				t = strings.ToLower(strings.TrimSpace(t))
				if t != "" {
					wantTopics[t] = struct{}{}
				}
			}
			if len(wantTopics) > 0 {
				var filtered []*gitlab.Project
				for _, p := range projObjs {
					matched := false
					for _, tp := range p.Topics {
						if _, ok := wantTopics[strings.ToLower(strings.TrimSpace(tp))]; ok {
							matched = true
							break
						}
					}
					if matched {
						filtered = append(filtered, p)
					}
				}
				projObjs = filtered
				// shrink printed list accordingly
				var slim []map[string]any
				for _, p := range projObjs {
					row := map[string]any{
						"id":                  p.ID,
						"path_with_namespace": p.PathWithNamespace,
						"http_url_to_repo":    p.HTTPURLToRepo,
						"web_url":             p.WebURL,
						"visibility":          p.Visibility,
						"default_branch":      p.DefaultBranch,
						"star_count":          p.StarCount,
					}
					slim = append(slim, row)
				}
				all = slim
			}
		}

		// Optional language filter using per-project /languages endpoint (any-of, case-insensitive)
		if strings.TrimSpace(languages) != "" && len(projObjs) > 0 {
			wantLangs := map[string]struct{}{}
			for t := range strings.SplitSeq(languages, ",") {
				t = strings.ToLower(strings.TrimSpace(t))
				if t != "" {
					wantLangs[t] = struct{}{}
				}
			}
			if langConc <= 0 {
				langConc = runtime.GOMAXPROCS(0)
			}
			if langConc > 64 {
				langConc = 64
			}
			type job struct{ p *gitlab.Project }
			type res struct {
				p      *gitlab.Project
				ok     bool
				sample string
				err    error
			}
			in := make(chan job)
			out := make(chan res)
			var wg sync.WaitGroup
			worker := func() {
				defer wg.Done()
				for j := range in {
					langs, err := client.GetProjectLanguages(ctx, j.p.ID)
					r := res{p: j.p}
					if err != nil {
						r.err = err
						out <- r
						continue
					}
					for k := range langs {
						lk := strings.ToLower(strings.TrimSpace(k))
						if _, ok := wantLangs[lk]; ok {
							r.ok = true
							r.sample = k
							break
						}
					}
					out <- r
				}
			}
			wg.Add(langConc)
			for i := 0; i < langConc; i++ {
				go worker()
			}
			go func() {
				for _, p := range projObjs {
					in <- job{p: p}
				}
				close(in)
			}()
			var filtered []*gitlab.Project
			var firstErr error
			for i := 0; i < len(projObjs); i++ {
				r := <-out
				if r.err != nil && firstErr == nil {
					firstErr = r.err
				}
				if r.ok {
					filtered = append(filtered, r.p)
				}
			}
			wg.Wait()
			projObjs = filtered
			// shrink printed list accordingly
			var slim []map[string]any
			for _, p := range projObjs {
				row := map[string]any{
					"id":                  p.ID,
					"path_with_namespace": p.PathWithNamespace,
					"http_url_to_repo":    p.HTTPURLToRepo,
					"web_url":             p.WebURL,
					"visibility":          p.Visibility,
					"default_branch":      p.DefaultBranch,
					"star_count":          p.StarCount,
				}
				slim = append(slim, row)
			}
			all = slim
			if firstErr != nil && len(projObjs) == 0 {
				return firstErr
			}
		}

		// Optional per-project path existence filter (exact path)
		if strings.TrimSpace(pathExists) != "" && len(projObjs) > 0 {
			var filtered []*gitlab.Project
			for _, p := range projObjs {
				ref := p.DefaultBranch
				if ref == "" {
					continue
				}
				_, resp, err := client.GL.RepositoryFiles.GetFile(p.ID, strings.TrimLeft(pathExists, "/"), &gitlab.GetFileOptions{Ref: new(ref)}, gitlab.WithContext(ctx))
				if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
					filtered = append(filtered, p)
				}
			}
			projObjs = filtered
			// also shrink the printed list accordingly
			var slim []map[string]any
			for _, p := range projObjs {
				row := map[string]any{
					"id":                  p.ID,
					"path_with_namespace": p.PathWithNamespace,
					"http_url_to_repo":    p.HTTPURLToRepo,
					"web_url":             p.WebURL,
					"visibility":          p.Visibility,
					"default_branch":      p.DefaultBranch,
					"path_exists":         pathExists,
					"star_count":          p.StarCount,
				}
				slim = append(slim, row)
			}
			all = slim
		}

		// Optional per-project path pattern filter (glob: *, ?, **)
		if strings.TrimSpace(pathPattern) != "" && len(projObjs) > 0 {
			if pathConc <= 0 {
				pathConc = runtime.GOMAXPROCS(0)
			}
			if pathConc > 64 {
				pathConc = 64
			}
			// compile glob to regex once
			glob := strings.TrimSpace(pathPattern)
			rgx, err := globToRegex(glob)
			if err != nil {
				return fmt.Errorf("invalid --path-pattern: %w", err)
			}
			type job struct{ p *gitlab.Project }
			type res struct {
				row       map[string]any
				matches   int
				firstPath string
				err       error
			}
			in := make(chan job)
			out := make(chan res)
			var wg sync.WaitGroup
			worker := func() {
				defer wg.Done()
				for j := range in {
					p := j.p
					ref := strings.TrimSpace(pathRef)
					if ref == "" && p.DefaultBranch != "" {
						ref = p.DefaultBranch
					}
					paths, err := client.ListRepoTreePaths(ctx, p.ID, ref, true, pathPerPage, pathMaxPages)
					r := res{}
					if err != nil {
						r.err = err
						out <- r
						continue
					}
					count := 0
					first := ""
					for _, path := range paths {
						if rgx.MatchString(path) {
							count++
							if first == "" {
								first = path
							}
						}
					}
					r.matches = count
					r.firstPath = first
					r.row = map[string]any{
						"id":                  p.ID,
						"path_with_namespace": p.PathWithNamespace,
						"http_url_to_repo":    p.HTTPURLToRepo,
						"web_url":             p.WebURL,
						"visibility":          p.Visibility,
						"default_branch":      p.DefaultBranch,
						"star_count":          p.StarCount,
					}
					out <- r
				}
			}
			wg.Add(pathConc)
			for i := 0; i < pathConc; i++ {
				go worker()
			}
			go func() {
				for _, p := range projObjs {
					in <- job{p: p}
				}
				close(in)
			}()
			var filtered []map[string]any
			var firstErr error
			for i := 0; i < len(projObjs); i++ {
				r := <-out
				if r.err != nil && firstErr == nil {
					firstErr = r.err
				}
				if r.matches > 0 {
					r.row["path_matches"] = r.matches
					if r.firstPath != "" {
						r.row["path_sample_match"] = r.firstPath
					}
					filtered = append(filtered, r.row)
				}
			}
			wg.Wait()
			all = filtered
			if firstErr != nil && len(all) == 0 {
				return firstErr
			}
		}

		// Optional per-project code content search filter
		if strings.TrimSpace(codeContent) != "" && len(projObjs) > 0 {
			if codeConc <= 0 {
				codeConc = runtime.GOMAXPROCS(0)
			}
			if codeConc > 64 {
				codeConc = 64
			} // cap
			type job struct{ p *gitlab.Project }
			type res struct {
				row       map[string]any
				matches   int
				firstPath string
				err       error
			}
			in := make(chan job)
			out := make(chan res)
			var wg sync.WaitGroup
			worker := func() {
				defer wg.Done()
				for j := range in {
					p := j.p
					ref := strings.TrimSpace(codeRef)
					if ref == "" && p.DefaultBranch != "" {
						ref = p.DefaultBranch
					}
					matches, err := client.CodeSearch(ctx, p.ID, codeContent, ref, codePerPage, codeMaxPages)
					r := res{}
					if err != nil {
						r.err = err
						out <- r
						continue
					}
					r.matches = len(matches)
					if len(matches) > 0 {
						r.firstPath = matches[0].Path
					}
					r.row = map[string]any{
						"id":                  p.ID,
						"path_with_namespace": p.PathWithNamespace,
						"http_url_to_repo":    p.HTTPURLToRepo,
						"web_url":             p.WebURL,
						"visibility":          p.Visibility,
						"default_branch":      p.DefaultBranch,
						"star_count":          p.StarCount,
					}
					out <- r
				}
			}
			wg.Add(codeConc)
			for i := 0; i < codeConc; i++ {
				go worker()
			}
			go func() {
				for _, p := range projObjs {
					in <- job{p: p}
				}
				close(in)
			}()
			var filtered []map[string]any
			var firstErr error
			for i := 0; i < len(projObjs); i++ {
				r := <-out
				if r.err != nil && firstErr == nil {
					firstErr = r.err
				}
				if r.matches > 0 {
					r.row["code_matches"] = r.matches
					if r.firstPath != "" {
						r.row["code_sample_path"] = r.firstPath
					}
					filtered = append(filtered, r.row)
				}
			}
			wg.Wait()
			all = filtered
			if firstErr != nil && len(all) == 0 {
				return firstErr
			}
		}

		// Persist results to SQLite (non-fatal)
		persistSearchResults(all, strings.TrimSpace(gitlabURL))

		// Output selection: default text; --json or --format=json => pretty JSON; --format=jsonl => JSON Lines
		w := cmd.OutOrStdout()
		var closer func() error
		if strings.TrimSpace(outputPath) != "" {
			f, err := os.Create(strings.TrimSpace(outputPath))
			if err != nil {
				return fmt.Errorf("open --output: %w", err)
			}
			w = f
			closer = f.Close
		}
		defer func() {
			if closer != nil {
				_ = closer()
			}
		}()
		fmtSel := strings.ToLower(strings.TrimSpace(format))
		if outputJSON && fmtSel == "" {
			fmtSel = fmtJSON
		}
		if fmtSel == fmtJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(all)
		}
		if fmtSel == fmtJSONL {
			return writeJSONL(w, all)
		}
		// text (pterm table)
		return writeSearchPTerm(w, all, codeContent, pathPattern)
	},
}

// writeSearchPTerm renders search results as a pterm table.
func writeSearchPTerm(w io.Writer, items []map[string]any, codeContent, pathPattern string) error {
	if len(items) == 0 {
		renderInfo(w, "No projects found")
		return nil
	}

	hasCode := strings.TrimSpace(codeContent) != ""
	hasPath := strings.TrimSpace(pathPattern) != ""

	// Build header
	header := []string{"ID", "Project", "Stars", "Visibility", "Last Activity", "URL"}
	if hasCode {
		header = []string{"ID", "Project", "Stars", "Code Matches", "Visibility", "URL"}
	} else if hasPath {
		header = []string{"ID", "Project", "Stars", "Path Matches", "Visibility", "URL"}
	}
	data := pterm.TableData{header}

	for _, it := range items {
		id := formatID(it["id"])
		proj := fmt.Sprint(it["path_with_namespace"])
		vis := fmt.Sprint(it["visibility"])
		url := fmt.Sprint(it["http_url_to_repo"])
		stars := formatID(it["star_count"])

		switch {
		case hasCode:
			matches := fmt.Sprint(it["code_matches"])
			data = append(data, []string{id, proj, stars, matches, vis, url})
		case hasPath:
			matches := fmt.Sprint(it["path_matches"])
			data = append(data, []string{id, proj, stars, matches, vis, url})
		default:
			activity := formatTimestamp(it["last_activity_at"])
			data = append(data, []string{id, proj, stars, vis, activity, url})
		}
	}

	if err := renderTable(w, data); err != nil {
		return err
	}

	// Footer with count
	renderInfo(w, fmt.Sprintf("Found %d projects", len(items)))
	return nil
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().StringVarP(&searchQuery, "query", "q", "", "Search query (matches name/path/description); optional")
	searchCmd.Flags().Int64Var(&perPage, "per-page", 50, "Projects per page")
	searchCmd.Flags().Int64Var(&maxPages, "max-pages", 1, "Maximum number of pages to fetch (0=all)")
	// Simple filters
	searchCmd.Flags().BoolVar(&owned, "owned", false, "Only projects owned by the authenticated user")
	searchCmd.Flags().BoolVar(&membership, "membership", false, "Projects the authenticated user is a member of")
	searchCmd.Flags().StringVar(&visibility, "visibility", "", "Filter by visibility: public|internal|private")
	searchCmd.Flags().BoolVar(&archivedOnly, "archived-only", false, "Only archived projects")
	// Path exists filter
	searchCmd.Flags().StringVar(&pathExists, "path-exists", "", "Keep only projects where this exact path exists (e.g., .gitlab-ci.yml)")

	// Path pattern filter using repository tree listing
	searchCmd.Flags().StringVar(&pathPattern, "path-pattern", "", "Glob pattern to match repository file paths (supports *, ?, **)")
	searchCmd.Flags().StringVar(&pathRef, "path-ref", "", "Git reference for path scan; defaults to project's default branch")
	searchCmd.Flags().IntVar(&pathPerPage, "path-per-page", 100, "Paths per page when scanning the repository tree")
	searchCmd.Flags().IntVar(&pathMaxPages, "path-max-pages", 10, "Max pages to fetch from repository tree per project")
	searchCmd.Flags().IntVar(&pathConc, "path-concurrency", 0, "Concurrency for per-project path scans (0=GOMAXPROCS)")

	// Advanced code search filters (per-project)
	searchCmd.Flags().StringVar(&codeContent, "code-content", "", "Filter projects by code content match (uses per-project code search)")
	searchCmd.Flags().StringVar(&codeRef, "code-ref", "", "Git reference (branch/tag/commit) for code search; defaults to project's default branch")
	searchCmd.Flags().IntVar(&codePerPage, "code-per-page", 20, "Code search results per page when filtering")
	searchCmd.Flags().IntVar(&codeMaxPages, "code-max-pages", 1, "Max pages to query per project for code search")
	searchCmd.Flags().IntVar(&codeConc, "code-concurrency", 0, "Concurrency for per-project code searches (0=GOMAXPROCS)")

	// Instance override for self-hosted/internal search (deprecated in favor of global --gitlab-url)
	searchCmd.Flags().StringVar(&instanceURL, "instance", "", "[DEPRECATED] Use --gitlab-url instead. Overrides GitLab instance just for this search.")
	_ = searchCmd.Flags().MarkDeprecated("instance", "use --gitlab-url instead; this flag will be removed in a future release")
	_ = searchCmd.Flags().MarkHidden("instance")

	// Language and topic filters
	searchCmd.Flags().StringVar(&languages, "language", "", "Comma-separated list of languages to filter by (matches any; uses per-project languages API)")
	searchCmd.Flags().StringVar(&topics, "topic", "", "Comma-separated list of project topics/tags to filter by (matches any)")
	searchCmd.Flags().IntVar(&langConc, "lang-concurrency", 0, "Concurrency for per-project language API calls (0=GOMAXPROCS)")

	// Output controls
	searchCmd.Flags().StringVar(&format, "format", "", "Output format: text|json|jsonl (default respects --json)")
	searchCmd.Flags().StringVar(&outputPath, "output", "", "Write output to file (default: stdout)")
}
