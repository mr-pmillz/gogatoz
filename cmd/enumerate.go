package cmd

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/bloodhound"
	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	enumorg "github.com/mr-pmillz/gogatoz/pkg/enumerate/org"
	report "github.com/mr-pmillz/gogatoz/pkg/enumerate/report"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/notify"
	"github.com/spf13/cobra"
)

var (
	// enumerate flags
	enumInput       string
	enumInputFormat string // auto|text|json|jsonl
	enumConc        int
	enumTimeout     string
	followIncludes  bool
	includeDepth    int
	deepIncludes    bool
	allowRemoteInc  bool
	remoteAllowlist string
	remoteMaxBytes  int64
	remoteTimeout   string
	remoteCacheTTL  string
	enumMode        string // quick|deep|pipeline-only
	onlyFindings    bool
	enumRedact      bool // mask plaintext secret values in findings (default: unredacted)
	// refs scanning
	refOne   string
	refsMany string
	maxRefs  int
	// group/org expansion
	enumGroup          string
	enumGroups         string
	enumGroupRecursive bool
	// inventory
	enumFetchProtected bool
	enumFetchRunners   bool
	runnerScope        string
	allowAdminScope    bool
	// logs scraping
	logScrape       bool
	logMaxPipelines int
	logMaxJobs      int
	// notifications
	webhookURL     string
	webhookHeaders []string
	webhookTimeout string
	// output formatting
	enumFormat     string // text|json|jsonl|sarif|glsast (default respects --json)
	enumOutputPath string
	// SARIF/GLSAST direct file output
	sarifOutputPath  string
	glsastOutputPath string
	// false positive filtering
	enumFilterFP bool
	// compliance scoring
	enumScore bool
	// MR comment and badge
	enumMRComment int64
	enumBadge     bool
	// bloodhound export
	enumBHExport string
	// threat intelligence
	enumThreatIntelURL  string
	enumThreatIntelFile string
)

var enumerateFunc = enumerate.EnumerateProjects

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate GitLab projects for CI/CD risks",
	Long:  "Enumerate scans a list of GitLab projects (IDs or path-with-namespace) and reports CI/CD configuration risks.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if token == "" && !noToken {
			return fmt.Errorf("GitLab token is required. Provide --token, set GITLAB_TOKEN, or use --no-token for unauthenticated access")
		}
		idents, err := loadIdents(enumInput)
		if err != nil {
			return err
		}

		// Build client (reuse global reliability + TLS flags)
		ctx := context.Background()
		clOpts := []gitlabx.Option{gitlabx.WithRateLimit(rateRPS, rateBurst), gitlabx.WithRetry(retryMax)}
		if ua := userAgent; strings.TrimSpace(ua) != "" {
			clOpts = append(clOpts, gitlabx.WithUserAgent(ua))
		}
		var idleTO, tlsTO, expectTO, reqTO time.Duration
		if s := strings.TrimSpace(httpIdleTimeout); s != "" {
			if d, e := time.ParseDuration(s); e != nil {
				return fmt.Errorf("invalid --http-idle-timeout: %w", e)
			} else {
				idleTO = d
			}
		}
		if s := strings.TrimSpace(httpTLSTimeout); s != "" {
			if d, e := time.ParseDuration(s); e != nil {
				return fmt.Errorf("invalid --http-tls-timeout: %w", e)
			} else {
				tlsTO = d
			}
		}
		if s := strings.TrimSpace(httpExpectTimeout); s != "" {
			if d, e := time.ParseDuration(s); e != nil {
				return fmt.Errorf("invalid --http-expect-timeout: %w", e)
			} else {
				expectTO = d
			}
		}
		if s := strings.TrimSpace(httpRequestTimeout); s != "" {
			if d, e := time.ParseDuration(s); e != nil {
				return fmt.Errorf("invalid --http-req-timeout: %w", e)
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
		client, err := gitlabx.New(strings.TrimSpace(gitlabURL), token, clOpts...)
		if err != nil {
			return err
		}

		// Expand groups into project identifiers if requested
		var groupIdents []string
		if strings.TrimSpace(enumGroup) != "" {
			groupIdents = append(groupIdents, strings.TrimSpace(enumGroup))
		}
		if strings.TrimSpace(enumGroups) != "" {
			for g := range strings.SplitSeq(enumGroups, ",") {
				g = strings.TrimSpace(g)
				if g != "" {
					groupIdents = append(groupIdents, g)
				}
			}
		}
		if len(groupIdents) > 0 {
			for _, g := range groupIdents {
				projs, gerr := enumorg.ListGroupProjects(ctx, client, g, enumGroupRecursive)
				if gerr != nil {
					return fmt.Errorf("list group projects (%s): %w", g, gerr)
				}
				idents = append(idents, projs...)
			}
		}
		// de-duplicate identifiers collected from file + groups
		{
			seen := map[string]struct{}{}
			uniq := make([]string, 0, len(idents))
			for _, s := range idents {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				if _, ok := seen[s]; ok {
					continue
				}
				seen[s] = struct{}{}
				uniq = append(uniq, s)
			}
			idents = uniq
		}
		if len(idents) == 0 {
			return fmt.Errorf("no targets provided; use --input or --group/--groups to supply projects")
		}

		// Options mapping
		opts := enumerate.Options{}
		if enumConc <= 0 {
			enumConc = runtime.GOMAXPROCS(0)
		}
		if enumConc > 128 {
			enumConc = 128
		}
		opts.Concurrency = enumConc
		if strings.TrimSpace(enumTimeout) != "" {
			if d, e := time.ParseDuration(enumTimeout); e != nil {
				return fmt.Errorf("invalid --timeout: %w", e)
			} else {
				opts.Timeout = d
			}
		}
		// Map include and analysis knobs
		opts.FollowIncludes = followIncludes
		if deepIncludes {
			opts.FollowIncludes = true
			if includeDepth < 3 {
				includeDepth = 3
			}
		}
		// Mode overrides flags if provided
		mode := strings.ToLower(strings.TrimSpace(enumMode))
		switch mode {
		case "quick":
			opts.FollowIncludes = false
			includeDepth = 0
			opts.SkipAnalyze = false
			allowRemoteInc = false
		case "deep":
			opts.FollowIncludes = true
			if includeDepth < 3 {
				includeDepth = 3
			}
			// allowRemoteInc honored from flag
			opts.SkipAnalyze = false
		case "pipeline-only", "pipeline_only", "pipelineonly":
			// speed-first: no analyzer
			opts.SkipAnalyze = true
			// keep include minimal for speed
			opts.FollowIncludes = false
			includeDepth = 0
		}
		opts.IncludeDepth = includeDepth
		opts.AllowRemoteIncludes = allowRemoteInc
		// Inventory
		opts.FetchProtected = enumFetchProtected
		opts.FetchRunners = enumFetchRunners
		opts.RunnerScope = runnerScope
		opts.AllowAdmin = allowAdminScope
		// Logs scraping
		opts.LogScrape = logScrape
		opts.LogMaxPipelines = logMaxPipelines
		opts.LogMaxJobs = logMaxJobs
		// Redaction (off by default: findings show real secret values)
		opts.Redact = enumRedact
		// Pass analysis controls from config file
		opts.Controls = controlsCfg
		// Threat intelligence feed
		if u := strings.TrimSpace(enumThreatIntelURL); u != "" {
			feed, ferr := config.LoadThreatIntelFeed(u)
			if ferr != nil {
				return fmt.Errorf("load threat intel feed: %w", ferr)
			}
			opts.ThreatIntel = feed
		} else if p := strings.TrimSpace(enumThreatIntelFile); p != "" {
			feed, ferr := config.LoadThreatIntelFile(p)
			if ferr != nil {
				return fmt.Errorf("load threat intel file: %w", ferr)
			}
			opts.ThreatIntel = feed
		}
		if strings.TrimSpace(remoteAllowlist) != "" {
			parts := strings.SplitSeq(remoteAllowlist, ",")
			for p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					opts.RemoteAllowlist = append(opts.RemoteAllowlist, p)
				}
			}
		}
		opts.RemoteMaxBytes = remoteMaxBytes
		if strings.TrimSpace(remoteTimeout) != "" {
			if d, e := time.ParseDuration(remoteTimeout); e != nil {
				return fmt.Errorf("invalid --remote-timeout: %w", e)
			} else {
				opts.RemoteTimeout = d
			}
		}
		if strings.TrimSpace(remoteCacheTTL) != "" {
			if d, e := time.ParseDuration(remoteCacheTTL); e != nil {
				return fmt.Errorf("invalid --remote-cache-ttl: %w", e)
			} else {
				opts.RemoteCacheTTL = d
			}
		}
		// Refs selection
		var refs []string
		if strings.TrimSpace(refOne) != "" {
			refs = append(refs, strings.TrimSpace(refOne))
		}
		if strings.TrimSpace(refsMany) != "" {
			for r := range strings.SplitSeq(refsMany, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					refs = append(refs, r)
				}
			}
		}
		if len(refs) > 0 {
			// dedupe while preserving order
			seen := map[string]struct{}{}
			uniq := make([]string, 0, len(refs))
			for _, r := range refs {
				if _, ok := seen[r]; ok {
					continue
				}
				seen[r] = struct{}{}
				uniq = append(uniq, r)
			}
			opts.Refs = uniq
		}
		if maxRefs < 0 {
			maxRefs = 0
		}
		opts.MaxRefs = maxRefs

		// Simple progress indicator when not JSON and verbose
		if !outputJSON && verbose {
			opts.Progress = func(r enumerate.Result) {
				_, err := fmt.Fprint(cmd.ErrOrStderr(), ".")
				if err != nil {
					return
				}
			}
		}

		scanStart := time.Now()
		results, err := enumerateFunc(ctx, client, idents, opts)
		if err != nil {
			// Non-fatal: still print any results gathered
			_, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", err)
			if err != nil {
				return err
			}
		}

		// Apply false positive filtering if requested
		if enumFilterFP {
			rules := analyze.DefaultFPRules()
			for i := range results {
				results[i].Findings = analyze.ApplyFPRules(results[i].Findings, rules)
			}
		}

		// Persist results to SQLite (non-fatal)
		persistEnumerateResults(results, strings.TrimSpace(gitlabURL))

		// BloodHound export (non-fatal)
		if bhPath := strings.TrimSpace(enumBHExport); bhPath != "" {
			bhBuilder := bloodhound.NewBuilder(strings.TrimSpace(gitlabURL))
			bhBuilder.AddEnumerateResults(results)
			bhBuilder.BuildTransitiveDependencies()
			bhBuilder.BuildSharedRunnerEdges()
			if err := bloodhound.Export(bhBuilder, bhPath); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: bloodhound export failed: %v\n", err)
			} else {
				nodes := bhBuilder.Nodes()
				edges := bhBuilder.Edges()
				fmt.Fprintf(cmd.ErrOrStderr(), "[bloodhound] exported %d nodes, %d edges to %s\n", len(nodes), len(edges), bhPath)
			}
		}

		// Optional notifications: post each finding to a webhook if configured
		if strings.TrimSpace(webhookURL) != "" {
			var to time.Duration
			if strings.TrimSpace(webhookTimeout) != "" {
				if d, e := time.ParseDuration(webhookTimeout); e != nil {
					return fmt.Errorf("invalid --webhook-timeout: %w", e)
				} else {
					to = d
				}
			}
			hdrs := map[string]string{}
			for _, h := range webhookHeaders {
				h = strings.TrimSpace(h)
				if h == "" {
					continue
				}
				// split on first ':'
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.TrimSpace(parts[1])
					if k != "" {
						hdrs[k] = v
					}
				}
			}
			n, nerr := notify.New(notify.Options{URL: strings.TrimSpace(webhookURL), Headers: hdrs, Timeout: to})
			if nerr != nil {
				return nerr
			}
			for _, r := range results {
				proj := r.ProjectPathWithNS
				meta := map[string]string{"web_url": r.WebURL}
				for _, f := range r.Findings {
					if err := n.SendFinding(ctx, proj, f, meta); err != nil {
						_, err := fmt.Fprintf(cmd.ErrOrStderr(), "notify warning: %v\n", err)
						if err != nil {
							return err
						}
					}
				}
			}
		}

		// Compute score if requested (before any output format)
		var scoreResult *analyze.ScoreResult
		if enumScore {
			var allFindings []analyze.Finding
			for _, r := range results {
				allFindings = append(allFindings, r.Findings...)
			}
			sr := analyze.ComputeScore(allFindings)
			scoreResult = &sr
		}

		// Write sidecar SARIF/GLSAST files if requested (alongside any primary output)
		if p := strings.TrimSpace(sarifOutputPath); p != "" {
			if sErr := writeSidecarSARIF(p, collectFindings(results), version); sErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to write SARIF: %v\n", sErr)
			}
		}
		if p := strings.TrimSpace(glsastOutputPath); p != "" {
			if sErr := writeSidecarGLSAST(p, collectFindings(results), version, scanStart); sErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to write GLSAST: %v\n", sErr)
			}
		}

		// Build report for MR comment/badge (needed before output to avoid skipping)
		repOpts := report.Options{OnlyFindings: onlyFindings}
		rep := report.Build(results, repOpts)
		rep.Score = scoreResult

		// Post-analysis: MR comment (requires single-project scan with known project ID)
		if enumMRComment > 0 && len(results) > 0 && results[0].ProjectID > 0 {
			commentBody := report.BuildMRCommentBody(rep, scoreResult)
			if mrErr := upsertMRComment(cmd.Context(), client, results[0].ProjectID, enumMRComment, commentBody); mrErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: MR comment failed: %v\n", mrErr)
			}
		}
		// Post-analysis: Badge (requires single-project scan with known project ID + score)
		if enumBadge && scoreResult != nil && len(results) == 1 && results[0].ProjectID > 0 {
			if badgeErr := client.UpsertComplianceBadge(cmd.Context(), results[0].ProjectID, scoreResult.Score, gitlabURL); badgeErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: badge update failed: %v\n", badgeErr)
			}
		}

		// Output selection: default text; --json or --format=json => pretty JSON; --format=jsonl => JSON Lines
		w := cmd.OutOrStdout()
		var closer func() error
		if strings.TrimSpace(enumOutputPath) != "" {
			f, err := os.Create(strings.TrimSpace(enumOutputPath))
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
		fmtSel := strings.ToLower(strings.TrimSpace(enumFormat))
		if outputJSON && fmtSel == "" {
			fmtSel = fmtJSON
		}
		if fmtSel == fmtJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(results)
		}
		if fmtSel == fmtJSONL {
			enc := json.NewEncoder(w)
			for _, r := range results {
				if onlyFindings && len(r.Findings) == 0 {
					continue
				}
				if err := enc.Encode(r); err != nil {
					return err
				}
			}
			return nil
		}
		// SARIF format
		if fmtSel == fmtSARIF {
			return WriteSARIF(w, collectFindings(results), version)
		}
		// GitLab SAST format
		if fmtSel == fmtGLSAST {
			return WriteGLSAST(w, collectFindings(results), version, scanStart, time.Now())
		}
		// html via report renderer
		if fmtSel == fmtHTML {
			return report.RenderHTML(w, rep, version)
		}
		// text via pterm report renderer
		if err := report.RenderPTerm(w, rep); err != nil {
			return err
		}
		if !outputJSON && verbose {
			_, err := fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(enumerateCmd)
	enumerateCmd.Flags().StringVarP(&enumInput, "input", "i", "", "Path to file with project identifiers (ID or path-with-namespace), one per line. Use '-' for stdin")
	enumerateCmd.Flags().IntVar(&enumConc, "concurrency", 16, "Number of concurrent workers")
	enumerateCmd.Flags().StringVar(&enumTimeout, "timeout", "", "Per-project timeout (e.g., 20s)")
	enumerateCmd.Flags().BoolVar(&followIncludes, "follow-includes", true, "Resolve includes transitively up to --include-depth")
	enumerateCmd.Flags().IntVar(&includeDepth, "include-depth", 2, "Depth for include resolution")
	enumerateCmd.Flags().BoolVar(&deepIncludes, "deep", false, "Enable deep mode (follow includes with depth >=3)")
	enumerateCmd.Flags().BoolVar(&allowRemoteInc, "allow-remote-includes", false, "Allow resolving remote includes (guarded by --remote-allowlist)")
	enumerateCmd.Flags().StringVar(&remoteAllowlist, "remote-allowlist", "", "Comma-separated host allowlist for remote includes (e.g., raw.githubusercontent.com,gitlab.com)")
	enumerateCmd.Flags().Int64Var(&remoteMaxBytes, "remote-max-bytes", 1<<20, "Max bytes to fetch for a remote include (default 1MiB)")
	enumerateCmd.Flags().StringVar(&remoteTimeout, "remote-timeout", "10s", "Timeout per remote include fetch (e.g., 10s)")
	enumerateCmd.Flags().StringVar(&remoteCacheTTL, "remote-cache-ttl", "", "Cross-call TTL cache for remote includes (e.g., 5m). Empty disables")
	enumerateCmd.Flags().BoolVar(&onlyFindings, "only-findings", false, "When printing text, only show projects with findings")
	enumerateCmd.Flags().BoolVar(&enumRedact, "redacted", false, "Redact (mask) plaintext secret values in findings; unredacted by default")
	// Notifications / webhook
	enumerateCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "Webhook URL to POST findings as JSON envelopes (one per finding)")
	enumerateCmd.Flags().StringArrayVar(&webhookHeaders, "webhook-header", nil, "Additional HTTP header for webhook POST (repeatable), e.g., 'Authorization: Bearer x'")
	enumerateCmd.Flags().StringVar(&webhookTimeout, "webhook-timeout", "", "Timeout per webhook request (e.g., 5s)")
	// Input format
	enumerateCmd.Flags().StringVar(&enumInputFormat, "input-format", "auto", "Input format for --input: auto|text|json|jsonl (auto detects per line)")
	// Modes and include depth
	enumerateCmd.Flags().StringVar(&enumMode, "mode", "", "Enumeration mode: quick|deep|pipeline-only (overrides include/analyzer defaults)")
	// Organization / groups expansion
	enumerateCmd.Flags().StringVar(&enumGroup, "group", "", "Group ID or full path to expand into projects")
	enumerateCmd.Flags().StringVar(&enumGroups, "groups", "", "Comma-separated group IDs or full paths to expand into projects")
	enumerateCmd.Flags().BoolVar(&enumGroupRecursive, "group-recursive", false, "Recursively include subgroup projects (best-effort)")
	// Inventory
	enumerateCmd.Flags().BoolVar(&enumFetchProtected, "protected-branches", false, "Fetch and include names of protected branches for each project")
	enumerateCmd.Flags().BoolVar(&enumFetchRunners, "runners", false, "Fetch runner summary (counts and executors); combine with --runners-scope")
	enumerateCmd.Flags().StringVar(&runnerScope, "runners-scope", "project", "Runner scope to query when --runners is set: project|group|instance")
	enumerateCmd.Flags().BoolVar(&allowAdminScope, "allow-admin-scope", false, "Allow admin-only operations (required for --runners-scope=instance)")
	// Log scraping (optional)
	enumerateCmd.Flags().BoolVar(&logScrape, "log-scrape", false, "Scrape recent job logs for key=value findings (best-effort, bounded)")
	enumerateCmd.Flags().IntVar(&logMaxPipelines, "log-max-pipelines", 3, "Max pipelines per ref to inspect for logs when --log-scrape is set")
	enumerateCmd.Flags().IntVar(&logMaxJobs, "log-max-jobs", 20, "Max jobs per pipeline to scan logs when --log-scrape is set")
	// Non-default refs scanning
	enumerateCmd.Flags().StringVar(&refOne, "ref", "", "Git reference (branch or tag) to scan in addition to the default branch")
	enumerateCmd.Flags().StringVar(&refsMany, "refs", "", "Comma-separated list of refs to scan per project (in addition to --ref)")
	enumerateCmd.Flags().IntVar(&maxRefs, "max-refs", 0, "Maximum number of refs to scan per project (0 = all provided)")
	// Output controls
	enumerateCmd.Flags().BoolVar(&enumFilterFP, "filter-false-positives", false, "Automatically identify and mark common false positive patterns")
	enumerateCmd.Flags().StringVar(&enumFormat, "format", "", "Output format: text|json|jsonl|html|sarif|glsast (default respects --json)")
	enumerateCmd.Flags().StringVar(&enumOutputPath, "output", "", "Write output to file (default: stdout)")
	enumerateCmd.Flags().StringVar(&sarifOutputPath, "sarif-output", "", "Write SARIF 2.1.0 report to file (in addition to primary output)")
	enumerateCmd.Flags().StringVar(&glsastOutputPath, "glsast-output", "", "Write GitLab SAST report (gl-sast-report.json) to file (in addition to primary output)")
	// Compliance scoring
	enumerateCmd.Flags().BoolVar(&enumScore, "score", false, "Compute and display compliance score (A-E letter grade)")
	// MR comment and badge
	enumerateCmd.Flags().Int64Var(&enumMRComment, "mr-comment", 0, "Post/update compliance comment on this MR IID (requires api scope token)")
	enumerateCmd.Flags().BoolVar(&enumBadge, "badge", false, "Create/update compliance badge on the project (requires api scope token)")
	// BloodHound export
	enumerateCmd.Flags().StringVar(&enumBHExport, "bloodhound-export", "", "Export results as BloodHound-CE OpenGraph ZIP (path to output .zip)")
	// Threat intelligence
	enumerateCmd.Flags().StringVar(&enumThreatIntelURL, "threat-intel-url", "", "URL to a JSON threat intelligence feed (blocked domains/IPs)")
	enumerateCmd.Flags().StringVar(&enumThreatIntelFile, "threat-intel-file", "", "Path to a local JSON threat intelligence feed file")
}

// loadIdents reads project identifiers from --input according to --input-format (auto|text|json|jsonl).
// auto-detect: first non-comment, non-whitespace character '[' => json array; '{' => jsonl; otherwise text.
//
//nolint:gocognit
func loadIdents(path string) ([]string, error) {
	var (
		f   *os.File
		err error
	)
	useStdin := strings.TrimSpace(path) == "-"
	if useStdin {
		f = os.Stdin
	} else {
		if strings.TrimSpace(path) == "" {
			return nil, nil
		}
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func(f *os.File) {
			err = f.Close()
			if err != nil {
				return
			}
		}(f)
	}
	br := bufio.NewReader(f)
	fmtSel := strings.ToLower(strings.TrimSpace(enumInputFormat))
	if fmtSel == fmtAuto || fmtSel == "" {
		// Peek first non-space/comment char without consuming
		for {
			b, e := br.Peek(1)
			if e != nil {
				if e == io.EOF {
					return nil, nil
				}
				return nil, e
			}
			c := b[0]
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				_, _ = br.ReadByte()
				continue
			}
			if c == '#' { // skip comment line
				if _, e := br.ReadString('\n'); e != nil && e != io.EOF {
					return nil, e
				}
				continue
			}
			switch c {
			case '[':
				fmtSel = fmtJSON
			case '{':
				fmtSel = fmtJSONL
			default:
				fmtSel = "text"
			}
			break
		}
	}
	switch fmtSel {
	case fmtJSONL:
		return loadIdentsJSONL(br)
	case fmtJSON:
		return loadIdentsJSONArray(br)
	default:
		return loadIdentsText(br)
	}
}

func loadIdentsText(r *bufio.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	var idents []string
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		idents = append(idents, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return idents, nil
}

func loadIdentsJSONL(r *bufio.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	// Allow long lines
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 10*1024*1024)
	var idents []string
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if !strings.HasPrefix(ln, "{") { // tolerate text lines intermixed
			idents = append(idents, ln)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			continue
		}
		if id := extractIdent(m); id != "" {
			idents = append(idents, id)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return idents, nil
}

func loadIdentsJSONArray(r *bufio.Reader) ([]string, error) {
	dec := json.NewDecoder(r)
	// Read start token '['
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, fmt.Errorf("expected JSON array")
	}
	var idents []string
	for dec.More() {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			return nil, err
		}
		if id := extractIdent(obj); id != "" {
			idents = append(idents, id)
		}
	}
	// Read closing ']'
	_, _ = dec.Token()
	return idents, nil
}

func extractIdent(m map[string]any) string {
	// Prefer path_with_namespace
	if v, ok := m["path_with_namespace"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	// Fallback: id numeric or string
	if v, ok := m["id"]; ok {
		switch t := v.(type) {
		case float64:
			return fmt.Sprintf("%d", int64(t))
		case int:
			return fmt.Sprintf("%d", t)
		case int64:
			return fmt.Sprintf("%d", t)
		case string:
			if strings.TrimSpace(t) != "" {
				return strings.TrimSpace(t)
			}
		}
	}
	return ""
}

// collectFindings aggregates all findings from enumerate results into a single slice.
func collectFindings(results []enumerate.Result) []analyze.Finding {
	var all []analyze.Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}
	return all
}

// writeSidecarSARIF writes a SARIF report to the specified file path.
func writeSidecarSARIF(path string, findings []analyze.Finding, toolVersion string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteSARIF(f, findings, toolVersion)
}

// writeSidecarGLSAST writes a GitLab SAST report to the specified file path.
func writeSidecarGLSAST(path string, findings []analyze.Finding, toolVersion string, start time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteGLSAST(f, findings, toolVersion, start, time.Now())
}

// upsertMRComment creates or updates the GoGatoZ compliance comment on a merge request.
func upsertMRComment(ctx context.Context, client *gitlabx.Client, projectID int64, mrIID int64, body string) error {
	notes, err := client.ListMergeRequestNotes(ctx, projectID, mrIID)
	if err != nil {
		return fmt.Errorf("list MR notes: %w", err)
	}
	identifier := report.MRCommentIdentifier()
	for _, note := range notes {
		if strings.Contains(note.Body, identifier) {
			_, err = client.UpdateMergeRequestNote(ctx, projectID, mrIID, note.ID, body)
			return err
		}
	}
	_, err = client.CreateMergeRequestNote(ctx, projectID, mrIID, body)
	return err
}
