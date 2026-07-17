package enumerate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/attack/secretsdump"
	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	defaultRunnerScope = "project"

	// DefaultConcurrency is the default number of concurrent workers for enumeration.
	DefaultConcurrency = 8

	// DefaultIncludeDepth is the default recursion depth for transitive includes.
	DefaultIncludeDepth = 2
)

// Result captures the outcome for a single project.
type Result struct {
	ProjectID         int64             `json:"project_id"`
	ProjectPathWithNS string            `json:"path_with_namespace"`
	WebURL            string            `json:"web_url"`
	DefaultBranch     string            `json:"default_branch"`
	StarCount         int64             `json:"star_count,omitempty"`
	ScannedRef        string            `json:"scanned_ref,omitempty"`
	HasCIPipeline     bool              `json:"has_ci_pipeline"`
	CISummary         string            `json:"ci_summary,omitempty"`
	Findings          []analyze.Finding `json:"findings,omitempty"`
	ProtectedBranches []string          `json:"protected_branches,omitempty"`
	// Runner enrichment (optional)
	RunnerScope     string         `json:"runner_scope,omitempty"`
	RunnersTotal    int            `json:"runners_total,omitempty"`
	RunnersOnline   int            `json:"runners_online,omitempty"`
	RunnerExecutors map[string]int `json:"runner_executors,omitempty"`
	// Correlation (optional)
	RunnerTagHits        map[string]int            `json:"runner_tag_hits,omitempty"`
	RunnerRiskyExecutors map[string]int            `json:"runner_risky_executors,omitempty"`
	RunnerTagExecutors   map[string]map[string]int `json:"runner_tag_executors,omitempty"`
	// Variable metadata (optional)
	ProjectVariables []analyze.VariableInfo `json:"project_variables,omitempty"`
	GroupVariables   []analyze.VariableInfo `json:"group_variables,omitempty"`
	// Log scraping (optional)
	LogFindingsCount int    `json:"log_findings_count,omitempty"`
	DurationMS       int64  `json:"duration_ms,omitempty"`
	Error            string `json:"error,omitempty"`
}

// Options controls enumeration behavior.
type Options struct {
	Concurrency    int
	Timeout        time.Duration
	FollowIncludes bool
	IncludeDepth   int
	// Remote include guardrails
	AllowRemoteIncludes bool
	RemoteAllowlist     []string
	RemoteMaxBytes      int64
	RemoteTimeout       time.Duration
	RemoteCacheTTL      time.Duration
	// Non-default refs to scan (if empty, scans default branch only)
	Refs    []string
	MaxRefs int
	// Inventory
	FetchProtected bool   // fetch protected branch names per project
	FetchRunners   bool   // fetch runner summary (counts)
	RunnerScope    string // project|group|instance (default: project)
	AllowAdmin     bool   // allow admin-only operations when RunnerScope=instance
	// Logs scraping (optional)
	LogScrape       bool // scrape recent job logs for key=value findings
	LogMaxPipelines int  // cap pipelines per ref
	LogMaxJobs      int  // cap jobs per pipeline
	// Variable metadata
	FetchVariables bool // fetch project and group CI/CD variable metadata (requires api scope)
	// Analysis
	SkipAnalyze bool                    // when true, parse and summarize but skip analyzer passes
	Redact      bool                    // when true, mask plaintext secret values in findings (default: unredacted)
	Controls    *config.ControlsConfig  // per-detection configuration (nil = use defaults)
	ThreatIntel *config.ThreatIntelFeed // external threat intel feed (nil = use hardcoded blocklist only)
	// Progress, if set, is called once per completed project result.
	Progress func(Result)
}

func appendError(r *Result, msg string) {
	if r.Error != "" {
		r.Error += "; "
	}
	r.Error += msg
}

func applyRunnerInfo(r *Result, runs []gitlabx.RunnerInfo) {
	r.RunnerExecutors = map[string]int{}
	r.RunnersTotal = len(runs)
	for _, rn := range runs {
		if rn.Online {
			r.RunnersOnline++
		}
		if exec := strings.TrimSpace(strings.ToLower(rn.Executor)); exec != "" {
			r.RunnerExecutors[exec]++
		}
	}
}

// dedup removes duplicate, empty, and comment-prefixed identifiers, preserving order.
func dedup(idents []string) []string {
	uniq := make([]string, 0, len(idents))
	seen := map[string]struct{}{}
	for _, s := range idents {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if _, ok := seen[s]; !ok {
			uniq = append(uniq, s)
			seen[s] = struct{}{}
		}
	}
	return uniq
}

// EnumerateProjectsStream scans the given identifiers and calls emit for each completed result.
// Unlike EnumerateProjects, it does not accumulate results in memory.
// The emit function is called from worker goroutines and is serialized internally.
func EnumerateProjectsStream(ctx context.Context, cl *gitlabx.Client, idents []string, opts Options, emit func(Result)) error {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.IncludeDepth <= 0 {
		opts.IncludeDepth = DefaultIncludeDepth
	}
	uniq := dedup(idents)
	slog.Info("enumerate starting", "projects", len(uniq), "concurrency", opts.Concurrency, "follow_includes", opts.FollowIncludes)

	type job struct{ ident string }
	jobs := make(chan job)

	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(opts.Concurrency)
	for i := 0; i < opts.Concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := range jobs {
				refs := determineRefs(opts)
				if len(refs) == 0 {
					refs = []string{""}
				}
				for _, rf := range refs {
					res := scanOne(ctx, cl, j.ident, opts, rf)
					if opts.Progress != nil {
						opts.Progress(res)
					}
					// Serializes emit across workers. EnumerateProjects wraps
					// emit with its own lock — redundant there but needed for
					// direct callers of Stream with non-thread-safe callbacks.
					mu.Lock()
					emit(res)
					mu.Unlock()
				}
			}
		}()
	}

	for _, id := range uniq {
		jobs <- job{ident: id}
	}
	close(jobs)
	wg.Wait()
	return nil
}

// EnumerateProjects scans the given identifiers (project IDs or path-with-namespace) for CI/CD issues.
func EnumerateProjects(ctx context.Context, cl *gitlabx.Client, idents []string, opts Options) ([]Result, error) {
	var mu sync.Mutex
	var results []Result
	err := EnumerateProjectsStream(ctx, cl, idents, opts, func(r Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	})
	return results, err
}

//nolint:gocognit // scanOne orchestrates network calls + parsing + analysis; kept as a single flow for performance and simplicity
func scanOne(ctx context.Context, cl *gitlabx.Client, ident string, opts Options, ref string) Result {
	var r Result
	start := time.Now()
	defer func() { r.DurationMS = time.Since(start).Milliseconds() }()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	proj, _, err := cl.GL.Projects.GetProject(ident, nil, gitlab.WithContext(ctx))
	if err != nil {
		r.Error = fmt.Sprintf("get project: %v", err)
		return r
	}
	r.ProjectID = proj.ID
	r.ProjectPathWithNS = proj.PathWithNamespace
	r.WebURL = proj.WebURL
	r.DefaultBranch = proj.DefaultBranch
	r.StarCount = proj.StarCount
	// Optional: fetch protected branches inventory
	if opts.FetchProtected {
		if list, err := cl.GetProtectedBranches(ctx, proj.ID, 100, 0); err == nil {
			r.ProtectedBranches = list
		} else {
			appendError(&r, fmt.Sprintf("protected branches: %v", err))
		}
		r.Findings = append(r.Findings, checkBranchProtection(ctx, cl, proj.ID, proj.DefaultBranch)...)
	}
	// Optional: fetch runner summary based on scope
	var fetchedRunners []gitlabx.RunnerInfo
	if opts.FetchRunners {
		scope := strings.ToLower(strings.TrimSpace(opts.RunnerScope))
		if scope == "" {
			scope = defaultRunnerScope
		}
		r.RunnerScope = scope
		switch scope {
		case defaultRunnerScope:
			if runs, err := cl.AccumulateProjectRunners(ctx, proj.ID); err == nil {
				fetchedRunners = runs
				applyRunnerInfo(&r, runs)
			} else {
				appendError(&r, fmt.Sprintf("runners(project): %v", err))
			}
		case "group":
			var gid any
			if proj.Namespace != nil {
				if proj.Namespace.ID != 0 {
					gid = proj.Namespace.ID
				} else if strings.TrimSpace(proj.Namespace.FullPath) != "" {
					if g, _, gerr := cl.GL.Groups.GetGroup(proj.Namespace.FullPath, nil, gitlab.WithContext(ctx)); gerr == nil {
						gid = g.ID
					} else {
						appendError(&r, fmt.Sprintf("group lookup: %v", gerr))
					}
				}
			}
			if gid == nil || gid == int64(0) {
				appendError(&r, "no group namespace for project")
			} else if runs, err := cl.AccumulateGroupRunners(ctx, gid); err == nil {
				fetchedRunners = runs
				applyRunnerInfo(&r, runs)
			} else {
				appendError(&r, fmt.Sprintf("runners(group): %v", err))
			}
		case "instance":
			if !opts.AllowAdmin {
				appendError(&r, "instance runner listing requires admin and --allow-admin-scope")
			} else if runs, err := cl.AccumulateAllRunners(ctx); err == nil {
				fetchedRunners = runs
				applyRunnerInfo(&r, runs)
			} else {
				appendError(&r, fmt.Sprintf("runners(instance): %v", err))
			}
		default:
			appendError(&r, fmt.Sprintf("unknown runner scope: %s", scope))
		}
	}

	// Optional: fetch CI/CD variable metadata for inheritance analysis
	var projectVars, groupVars []analyze.VariableInfo
	if opts.FetchVariables {
		if pv, err := FetchProjectVariables(ctx, cl, proj.ID); err == nil {
			projectVars = pv
			r.ProjectVariables = pv
		} else {
			appendError(&r, fmt.Sprintf("project variables: %v", err))
		}
		if proj.Namespace != nil && proj.Namespace.ID != 0 {
			if gv, err := FetchGroupVariables(ctx, cl, proj.Namespace.ID); err == nil {
				groupVars = gv
				r.GroupVariables = gv
			} else {
				appendError(&r, fmt.Sprintf("group variables: %v", err))
			}
		}
	}

	refToUse := strings.TrimSpace(ref)
	if refToUse == "" {
		refToUse = proj.DefaultBranch
	}
	r.ScannedRef = refToUse
	if refToUse == "" {
		// No ref to scan (no default branch and none provided) => likely empty project
		r.CISummary = "no default branch"
		return r
	}

	file, resp, err := cl.GL.RepositoryFiles.GetFile(proj.ID, ".gitlab-ci.yml", &gitlab.GetFileOptions{Ref: new(refToUse)}, gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			r.CISummary = "no .gitlab-ci.yml"
			return r
		}
		r.Error = fmt.Sprintf("get .gitlab-ci.yml: %v", err)
		return r
	}

	decoded, decErr := base64.StdEncoding.DecodeString(file.Content)
	if decErr != nil {
		r.Error = fmt.Sprintf("decode ci file: %v", decErr)
		return r
	}
	ciDoc, perr := pipeline.Parse(strings.NewReader(string(decoded)))
	if perr != nil {
		r.Error = fmt.Sprintf("parse ci: %v", perr)
		return r
	}

	// Optionally resolve includes transitively
	ciDocResolved := ciDoc
	if opts.FollowIncludes && len(ciDoc.Includes) > 0 {
		merged, ierr := pipeline.ResolveIncludesWithOptions(ctx, cl, proj.ID, refToUse, ciDoc, opts.IncludeDepth, pipeline.ResolveOptions{
			AllowRemote:      opts.AllowRemoteIncludes,
			RemoteAllowHosts: opts.RemoteAllowlist,
			RemoteMaxBytes:   opts.RemoteMaxBytes,
			RemoteTimeout:    opts.RemoteTimeout,
			RemoteCacheTTL:   opts.RemoteCacheTTL,
		})
		if ierr != nil {
			appendError(&r, ierr.Error())
		}
		if merged != nil {
			ciDocResolved = merged
		}
	}

	r.HasCIPipeline = true
	r.CISummary = ciDocResolved.DebugString()

	// Correlate job tags with fetched runners (if any)
	if opts.FetchRunners && len(fetchedRunners) > 0 {
		// Collect unique job tags from the resolved pipeline
		jobTags := map[string]struct{}{}
		for _, j := range ciDocResolved.Jobs {
			for _, t := range j.Tags {
				tag := strings.ToLower(strings.TrimSpace(t))
				if tag != "" {
					jobTags[tag] = struct{}{}
				}
			}
		}
		if len(jobTags) > 0 {
			if r.RunnerTagHits == nil {
				r.RunnerTagHits = map[string]int{}
			}
			if r.RunnerRiskyExecutors == nil {
				r.RunnerRiskyExecutors = map[string]int{}
			}
			if r.RunnerTagExecutors == nil {
				r.RunnerTagExecutors = map[string]map[string]int{}
			}
			for _, rn := range fetchedRunners {
				exec := strings.ToLower(strings.TrimSpace(rn.Executor))
				// Tag intersections
				for _, t := range rn.TagList {
					tag := strings.ToLower(strings.TrimSpace(t))
					if tag == "" {
						continue
					}
					if _, ok := jobTags[tag]; ok {
						r.RunnerTagHits[tag]++
						// Per-tag executor mapping
						if exec != "" {
							if r.RunnerTagExecutors[tag] == nil {
								r.RunnerTagExecutors[tag] = map[string]int{}
							}
							r.RunnerTagExecutors[tag][exec]++
						}
					}
				}
				// Risky executor classes
				if exec == "shell" || exec == "docker" {
					r.RunnerRiskyExecutors[exec]++
				}
			}
		}
	}

	// Optional: scrape recent job logs for key=value findings (best-effort)
	if opts.LogScrape {
		mp := opts.LogMaxPipelines
		if mp <= 0 {
			mp = 3
		}
		mj := opts.LogMaxJobs
		if mj <= 0 {
			mj = 20
		}
		finds, lerr := secretsdump.ScrapeJobLogs(ctx, cl, proj.ID, refToUse, mp, mj)
		if lerr != nil {
			appendError(&r, fmt.Sprintf("log scrape: %v", lerr))
		} else {
			r.LogFindingsCount = len(finds)
		}
	}

	if opts.SkipAnalyze {
		return r
	}

	var aopts []analyze.Option
	if opts.Redact {
		aopts = append(aopts, analyze.WithRedactedSecrets())
	}
	if opts.Controls != nil {
		aopts = append(aopts, analyze.WithControls(opts.Controls))
	}
	if opts.ThreatIntel != nil {
		aopts = append(aopts, analyze.WithThreatIntel(opts.ThreatIntel))
	}
	if opts.FetchVariables && (len(projectVars) > 0 || len(groupVars) > 0) {
		aopts = append(aopts, analyze.WithVariableData(&analyze.VariableData{
			ProjectVars: projectVars,
			GroupVars:   groupVars,
		}))
	}
	findings, ferr := analyze.Run(ciDocResolved, aopts...)
	if ferr != nil && !errors.Is(ferr, analyze.ErrPartial) {
		// Non-fatal; still return parsed info
		r.Error = fmt.Sprintf("analysis error: %v", ferr)
	}
	r.Findings = findings
	// Post-analysis: emit executor-specific findings before severity adjustment
	addExecutorFindings(&r, ciDocResolved)
	// Post-analysis: adjust severities based on runner risk correlation, if available
	adjustFindingsForRunnerRisk(&r, ciDocResolved)
	// Post-analysis: downgrade severities when job rules appear to restrict to protected branches
	adjustFindingsForProtectedBranches(&r, ciDocResolved)
	slog.Debug("project scanned", "project", r.ProjectPathWithNS, "findings", len(r.Findings), "ref", ref, "duration_ms", r.DurationMS)
	return r
}

// determineRefs returns the list of refs to scan based on options, deduped and capped.
func determineRefs(opts Options) []string {
	if len(opts.Refs) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, r := range opts.Refs {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
		if opts.MaxRefs > 0 && len(out) >= opts.MaxRefs {
			break
		}
	}
	return out
}
