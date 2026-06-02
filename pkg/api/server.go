package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Config controls the HTTP API server.
type Config struct {
	BaseURL    string
	ListenAddr string
}

// Server provides HTTP endpoints that expose GoGatoZ functionality to tools/agents.
// It is intentionally thin and stateless; most options are provided per-request.
type enumeratorFn func(ctx context.Context, cl *gitlabx.Client, idents []string, opts enumerate.Options) ([]enumerate.Result, error)

type searcherFn func(ctx context.Context, cl *gitlabx.Client, opts searchProjectsOptions) ([]searchProjectResult, error)

type Server struct {
	cfg      Config
	engine   *gin.Engine
	enumFn   enumeratorFn
	searchFn searcherFn
}

// NewServer builds the HTTP server with all routes mounted.
func NewServer(cfg Config) *Server {
	g := gin.New()
	g.Use(gin.Recovery())
	g.Use(gin.Logger())

	s := &Server{cfg: cfg, engine: g, enumFn: enumerate.EnumerateProjects, searchFn: searchProjects}
	s.routes()
	return s
}

func (s *Server) routes() {
	r := s.engine
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	r.POST("/auth/validate", s.handleValidate)

	enum := r.Group("/enumerate")
	{
		enum.POST("/repo", s.handleEnumerateRepo)
		enum.POST("/repos", s.handleEnumerateRepos)
		enum.POST("/org", s.handleEnumerateGroup)
		enum.POST("/group", s.handleEnumerateGroup)
		// Streaming NDJSON endpoint: streams results as they are produced
		enum.POST("/stream", s.handleEnumerateStream)
	}

	// Search endpoints
	search := r.Group("/search")
	{
		search.POST("/projects", s.handleSearchProjects)
	}
}

// Run starts serving on the configured address (blocking).
func (s *Server) Run() error { return s.engine.Run(s.cfg.ListenAddr) }

// --- Requests / Options -----------------------------------------------

type authInput struct {
	Token   string `json:"token"`
	BaseURL string `json:"gitlab_url"`
}

type enumerateOptions struct {
	Concurrency     int      `json:"concurrency"`
	Timeout         string   `json:"timeout"`
	FollowIncludes  bool     `json:"follow_includes"`
	IncludeDepth    int      `json:"include_depth"`
	AllowRemote     bool     `json:"allow_remote_includes"`
	RemoteAllowlist []string `json:"remote_allowlist"`
	RemoteMaxBytes  int64    `json:"remote_max_bytes"`
	RemoteTimeout   string   `json:"remote_timeout"`
	RemoteCacheTTL  string   `json:"remote_cache_ttl"`
	FetchProtected  bool     `json:"fetch_protected"`
	FetchRunners    bool     `json:"fetch_runners"`
	RunnerScope     string   `json:"runner_scope"`
	AllowAdmin      bool     `json:"allow_admin"`
	// logs scraping
	LogScrape       bool     `json:"log_scrape"`
	LogMaxPipelines int      `json:"log_max_pipelines"`
	LogMaxJobs      int      `json:"log_max_jobs"`
	Refs            []string `json:"refs"`
	MaxRefs         int      `json:"max_refs"`
}

func (eo enumerateOptions) toEnumerateOpts() enumerate.Options {
	var timeout time.Duration
	if strings.TrimSpace(eo.Timeout) != "" {
		if d, err := time.ParseDuration(eo.Timeout); err == nil {
			timeout = d
		}
	}
	return enumerate.Options{
		Concurrency:         eo.Concurrency,
		Timeout:             timeout,
		FollowIncludes:      eo.FollowIncludes,
		IncludeDepth:        eo.IncludeDepth,
		AllowRemoteIncludes: eo.AllowRemote,
		RemoteAllowlist:     eo.RemoteAllowlist,
		FetchProtected:      eo.FetchProtected,
		FetchRunners:        eo.FetchRunners,
		RunnerScope:         eo.RunnerScope,
		AllowAdmin:          eo.AllowAdmin,
		LogScrape:           eo.LogScrape,
		LogMaxPipelines:     eo.LogMaxPipelines,
		LogMaxJobs:          eo.LogMaxJobs,
		Refs:                eo.Refs,
		MaxRefs:             eo.MaxRefs,
	}
}

type enumRepoInput struct {
	Auth  authInput        `json:"auth"`
	Ident string           `json:"ident"`
	Opts  enumerateOptions `json:"options"`
}

type enumReposInput struct {
	Auth   authInput        `json:"auth"`
	Idents []string         `json:"idents"`
	Opts   enumerateOptions `json:"options"`
}

type enumGroupInput struct {
	Auth             authInput        `json:"auth"`
	Group            string           `json:"group"` // ID or full_path
	IncludeSubgroups bool             `json:"include_subgroups"`
	Opts             enumerateOptions `json:"options"`
}

// --- Handlers ----------------------------------------------------------

func (s *Server) handleValidate(c *gin.Context) {
	var in authInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	base := strings.TrimSpace(firstNonEmpty(in.BaseURL, s.cfg.BaseURL))
	tok := strings.TrimSpace(firstNonEmpty(in.Token, getenv("GITLAB_TOKEN")))
	if tok == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	cl, err := gitlabx.New(base, tok)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	usr, resp, err := cl.Ping(ctx)
	if err != nil {
		st := http.StatusBadGateway
		if resp != nil {
			st = resp.StatusCode
		}
		c.JSON(st, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "user": usr})
}

func (s *Server) handleEnumerateRepo(c *gin.Context) {
	var in enumRepoInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(in.Ident) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ident is required"})
		return
	}
	res, err := s.enumerate(c.Request.Context(), in.Auth, []string{in.Ident}, in.Opts)
	if err != nil {
		statusFromErr(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (s *Server) handleEnumerateRepos(c *gin.Context) {
	var in enumReposInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(in.Idents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idents must be non-empty"})
		return
	}
	res, err := s.enumerate(c.Request.Context(), in.Auth, in.Idents, in.Opts)
	if err != nil {
		statusFromErr(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (s *Server) handleEnumerateGroup(c *gin.Context) {
	var in enumGroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	base := strings.TrimSpace(firstNonEmpty(in.Auth.BaseURL, s.cfg.BaseURL))
	tok := strings.TrimSpace(firstNonEmpty(in.Auth.Token, getenv("GITLAB_TOKEN")))
	if tok == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	client, err := gitlabx.New(base, tok)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	groupID := any(in.Group)
	if id, err := strconv.Atoi(in.Group); err == nil {
		groupID = id
	}

	// list projects in group
	opt := &gitlab.ListGroupProjectsOptions{ListOptions: gitlab.ListOptions{PerPage: 100}}
	var idents []string
	for {
		projs, resp, err := client.GL.Groups.ListGroupProjects(groupID, opt)
		if err != nil {
			c.JSON(statusOf(resp), gin.H{"error": err.Error()})
			return
		}
		for _, p := range projs {
			idents = append(idents, p.PathWithNamespace)
		}
		if resp.CurrentPage >= resp.TotalPages || len(projs) == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	if len(idents) == 0 {
		c.JSON(http.StatusOK, []enumerate.Result{})
		return
	}
	res, err := s.enumerateWithClient(c.Request.Context(), client, idents, in.Opts)
	if err != nil {
		statusFromErr(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// handleEnumerateStream streams NDJSON lines for each project result as it completes.
func (s *Server) handleEnumerateStream(c *gin.Context) {
	var in enumReposInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(in.Idents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idents must be non-empty"})
		return
	}
	base := strings.TrimSpace(firstNonEmpty(in.Auth.BaseURL, s.cfg.BaseURL))
	tok := strings.TrimSpace(firstNonEmpty(in.Auth.Token, getenv("GITLAB_TOKEN")))
	if tok == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	client, err := gitlabx.New(base, tok)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	opts := in.Opts.toEnumerateOpts()

	w := c.Writer
	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Status(http.StatusOK)
	fl, ok := w.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
		return
	}
	enc := json.NewEncoder(w)
	var mu sync.Mutex
	opts.Progress = func(res enumerate.Result) {
		mu.Lock()
		_ = enc.Encode(res)
		fl.Flush()
		mu.Unlock()
	}
	ctx := c.Request.Context()
	_, err = s.enumFn(ctx, client, in.Idents, opts)
	if err != nil {
		// Emit a final error line (best-effort)
		mu.Lock()
		_ = enc.Encode(gin.H{"error": err.Error()})
		fl.Flush()
		mu.Unlock()
	}
}

// --- helpers -----------------------------------------------------------

func (s *Server) enumerate(ctx context.Context, a authInput, idents []string, opts enumerateOptions) ([]enumerate.Result, error) {
	base := strings.TrimSpace(firstNonEmpty(a.BaseURL, s.cfg.BaseURL))
	tok := strings.TrimSpace(firstNonEmpty(a.Token, getenv("GITLAB_TOKEN")))
	if tok == "" {
		return nil, httpError{code: http.StatusBadRequest, msg: "missing token"}
	}
	client, err := gitlabx.New(base, tok)
	if err != nil {
		return nil, httpError{code: http.StatusBadRequest, msg: err.Error()}
	}
	return s.enumerateWithClient(ctx, client, idents, opts)
}

func (s *Server) enumerateWithClient(ctx context.Context, client *gitlabx.Client, idents []string, in enumerateOptions) ([]enumerate.Result, error) {
	opts := in.toEnumerateOpts()
	ctx2 := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx2, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	return enumerate.EnumerateProjects(ctx2, client, idents, opts)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func getenv(k string) string {
	v := os.Getenv(k)
	return strings.TrimSpace(strings.ReplaceAll(v, "\x00", ""))
}

// httpError allows returning an HTTP code via error path
type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func statusFromErr(c *gin.Context, err error) {
	var he httpError
	if errors.As(err, &he) {
		c.JSON(he.code, gin.H{"error": he.msg})
		return
	}
	c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
}

func statusOf(resp *gitlab.Response) int {
	if resp == nil || resp.Response == nil {
		return http.StatusBadGateway
	}
	return resp.StatusCode
}

// --- Search types and handler -------------------------------------------

// searchProjectsOptions defines filters for project search.
//
//nolint:tagliatelle // HTTP JSON uses snake_case keys
type searchProjectsOptions struct {
	Query        string `json:"query"`
	PerPage      int64  `json:"per_page"`
	MaxPages     int64  `json:"max_pages"`
	Owned        bool   `json:"owned"`
	Membership   bool   `json:"membership"`
	Visibility   string `json:"visibility"`
	Archived     bool   `json:"archived"`
	PathExists   string `json:"path_exists"`
	PathPattern  string `json:"path_pattern"`
	CodeContent  string `json:"code_content"`
	Language     string `json:"language"`
	Topic        string `json:"topic"`
	Ref          string `json:"ref"`
	PathPerPage  int    `json:"path_per_page"`
	PathMaxPages int    `json:"path_max_pages"`
	CodePerPage  int    `json:"code_per_page"`
	CodeMaxPages int    `json:"code_max_pages"`
	Concurrency  int    `json:"concurrency"`
}

// searchProjectsInput is the POST body for /search/projects.
//
//nolint:tagliatelle
type searchProjectsInput struct {
	Auth authInput             `json:"auth"`
	Opts searchProjectsOptions `json:"options"`
}

// searchProjectResult represents a single project returned from search.
//
//nolint:tagliatelle
type searchProjectResult struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	Visibility        string `json:"visibility"`
	DefaultBranch     string `json:"default_branch"`
	StarCount         int64  `json:"star_count"`
	Archived          bool   `json:"archived,omitempty"`
}

// searchProjectsResponse is the envelope returned by /search/projects.
//
//nolint:tagliatelle
type searchProjectsResponse struct {
	Projects   []searchProjectResult `json:"projects"`
	TotalFound int                   `json:"total_found"`
	Returned   int                   `json:"returned"`
}

// validVisibility checks whether a visibility string is valid for the GitLab API.
func validVisibility(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "public", "internal", "private":
		return true
	default:
		return false
	}
}

// handleSearchProjects searches for GitLab projects using the API with optional filters.
func (s *Server) handleSearchProjects(c *gin.Context) {
	var in searchProjectsInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	base := strings.TrimSpace(firstNonEmpty(in.Auth.BaseURL, s.cfg.BaseURL))
	tok := strings.TrimSpace(firstNonEmpty(in.Auth.Token, getenv("GITLAB_TOKEN")))
	if tok == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	if !validVisibility(in.Opts.Visibility) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid visibility: use public, internal, or private"})
		return
	}
	client, err := gitlabx.New(base, tok)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	results, err := s.searchFn(ctx, client, in.Opts)
	if err != nil {
		statusFromErr(c, err)
		return
	}
	c.JSON(http.StatusOK, searchProjectsResponse{
		Projects:   results,
		TotalFound: len(results),
		Returned:   len(results),
	})
}
