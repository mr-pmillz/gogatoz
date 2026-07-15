package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/secretscan"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	ssOutputDir    string
	ssScanners     string
	ssConcurrency  int
	ssCloneDepth   int
	ssDiscardRepos bool
	ssQuery        string
	ssVisibility   string
	ssPerPage      int64
	ssMaxPages     int64
	ssOwned        bool
	ssMembership   bool
	ssTopic        string
	ssLanguage     string
	ssFormat       string
	ssOutput       string
	ssScanDir      string
	ssRedact       bool
)

var secretscanCmd = &cobra.Command{
	Use:   "secretscan",
	Short: "Clone GitLab projects and scan for secrets",
	Long: `Discovers GitLab projects via the API, clones them locally, and scans
each repository for secrets using external tools (TruffleHog, Gitleaks, Titus).

Supports both authenticated scanning (with GITLAB_TOKEN for internal/private
projects) and unauthenticated scanning (--no-token for public projects only).

At least one scanner tool must be installed on your PATH. Use --scanners to
select specific tools or leave as "auto" to detect all available scanners.

Results are persisted to the local SQLite database for later querying.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		scanDir := strings.TrimSpace(ssScanDir)
		outputDir := strings.TrimSpace(ssOutputDir)

		// Validate required flags
		if scanDir == "" && outputDir == "" {
			return fmt.Errorf("either --output-dir or --scan-dir is required")
		}

		// Build GitLab client (only needed when not using --scan-dir)
		var client *gitlabx.Client
		if scanDir == "" {
			if !noToken && strings.TrimSpace(token) == "" {
				return fmt.Errorf("GITLAB_TOKEN required for project discovery (use --no-token for public projects or --scan-dir for offline scanning)")
			}
			cl, err := buildSecretScanClient()
			if err != nil {
				return err
			}
			client = cl

			if verbose {
				if u, _, err := client.Ping(ctx); err == nil {
					slog.Info("authenticated", "username", u.Username)
				}
			}
		}

		opts := secretscan.Options{
			OutputDir:    outputDir,
			Scanners:     ssScanners,
			Concurrency:  ssConcurrency,
			CloneDepth:   ssCloneDepth,
			DiscardRepos: ssDiscardRepos,
			Redact:       ssRedact,
			Query:        ssQuery,
			Visibility:   ssVisibility,
			PerPage:      ssPerPage,
			MaxPages:     ssMaxPages,
			Owned:        ssOwned,
			Membership:   ssMembership,
			ScanDir:      scanDir,
			Progress: func(r secretscan.ScanResult) {
				if r.Error != "" {
					slog.Error("secret scan error", "project", r.PathWithNamespace, "error", r.Error)
				} else {
					slog.Info("secret scan complete", "project", r.PathWithNamespace, "findings", r.FindingsCount, "duration_ms", r.DurationMS)
				}
			},
		}

		effectiveToken := token
		if noToken {
			effectiveToken = ""
		}

		results, err := secretscan.Run(ctx, client, effectiveToken, opts)
		if err != nil {
			return err
		}

		// Persist to DB
		persistSecretScanResults(results, gitlabURL)

		// Render output
		w, closer, err := openOutputWriter(cmd, ssOutput)
		if err != nil {
			return err
		}
		if closer != nil {
			defer closer()
		}

		summary := secretscan.BuildSummary(results)
		return renderSecretScanOutput(w, results, summary, ssFormat)
	},
}

func init() {
	rootCmd.AddCommand(secretscanCmd)
	secretscanCmd.Flags().StringVarP(&ssOutputDir, "output-dir", "o", "", "Directory for cloned repos (required unless --scan-dir)")
	secretscanCmd.Flags().StringVar(&ssScanners, "scanners", "auto", "Scanners to use: trufflehog,gitleaks,titus or auto (default: auto-detect)")
	secretscanCmd.Flags().IntVar(&ssConcurrency, "concurrency", 4, "Number of concurrent clone+scan workers")
	secretscanCmd.Flags().IntVar(&ssCloneDepth, "clone-depth", 1, "Git clone depth (0 for full history)")
	secretscanCmd.Flags().BoolVar(&ssDiscardRepos, "discard-repos-after-scanning", false, "Remove each cloned repo after scanning to save disk space")
	secretscanCmd.Flags().StringVar(&ssQuery, "query", "", "Search query filter for project discovery")
	secretscanCmd.Flags().StringVar(&ssVisibility, "visibility", "", "Filter by visibility: public, internal, or private")
	secretscanCmd.Flags().Int64Var(&ssPerPage, "per-page", 50, "Results per API page (max 100)")
	secretscanCmd.Flags().Int64Var(&ssMaxPages, "max-pages", 0, "Maximum pages to fetch (0 = unlimited)")
	secretscanCmd.Flags().BoolVar(&ssOwned, "owned", false, "Only projects owned by the authenticated user")
	secretscanCmd.Flags().BoolVar(&ssMembership, "membership", false, "Only projects the user is a member of")
	secretscanCmd.Flags().StringVar(&ssTopic, "topic", "", "Comma-separated topic filter")
	secretscanCmd.Flags().StringVar(&ssLanguage, "language", "", "Comma-separated language filter")
	secretscanCmd.Flags().StringVar(&ssFormat, "format", "", "Output format: text|json|jsonl (default respects --json)")
	secretscanCmd.Flags().StringVar(&ssOutput, "output", "", "Write output to file (default: stdout)")
	secretscanCmd.Flags().StringVar(&ssScanDir, "scan-dir", "", "Scan pre-cloned repos in this directory (walks tree, finds .git dirs)")
	secretscanCmd.Flags().BoolVar(&ssRedact, "redact", false, "Redact secret values in output and database")
}

// buildSecretScanClient creates a GitLab client with the global HTTP/TLS options.
func buildSecretScanClient() (*gitlabx.Client, error) {
	clOpts := []gitlabx.Option{
		gitlabx.WithRateLimit(rateRPS, rateBurst),
		gitlabx.WithRetry(retryMax),
	}
	if ua := strings.TrimSpace(userAgent); ua != "" {
		clOpts = append(clOpts, gitlabx.WithUserAgent(ua))
	}

	var idleTO, tlsTO, expectTO, reqTO time.Duration
	for _, pair := range []struct {
		raw  string
		dest *time.Duration
		name string
	}{
		{httpIdleTimeout, &idleTO, "http-idle-timeout"},
		{httpTLSTimeout, &tlsTO, "http-tls-timeout"},
		{httpExpectTimeout, &expectTO, "http-expect-timeout"},
		{httpRequestTimeout, &reqTO, "http-req-timeout"},
	} {
		if s := strings.TrimSpace(pair.raw); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return nil, fmt.Errorf("invalid --%s: %w", pair.name, err)
			}
			*pair.dest = d
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
			return nil, fmt.Errorf("read --ca-cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-cert: no valid PEM certificates found")
		}
		clOpts = append(clOpts, gitlabx.WithRootCAs(pool))
	}
	clOpts = appendSOCKS5Option(clOpts)

	tok := token
	if noToken {
		tok = ""
	}
	return gitlabx.New(gitlabURL, tok, clOpts...)
}

// openOutputWriter returns a writer for command output and an optional closer.
func openOutputWriter(cmd *cobra.Command, path string) (io.Writer, func(), error) {
	if p := strings.TrimSpace(path); p != "" {
		f, err := os.Create(p)
		if err != nil {
			return nil, nil, fmt.Errorf("open --output: %w", err)
		}
		return f, func() { _ = f.Close() }, nil
	}
	return cmd.OutOrStdout(), nil, nil
}

// renderSecretScanOutput writes results in the requested format.
func renderSecretScanOutput(w io.Writer, results []secretscan.ScanResult, summary secretscan.Summary, fmtFlag string) error {
	fmtSel := strings.ToLower(strings.TrimSpace(fmtFlag))
	if outputJSON && fmtSel == "" {
		fmtSel = fmtJSON
	}
	if fmtSel == "" {
		fmtSel = fmtText
	}

	type fullOutput struct {
		Results []secretscan.ScanResult `json:"results"`
		Summary secretscan.Summary      `json:"summary"`
	}

	switch fmtSel {
	case fmtJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(fullOutput{Results: results, Summary: summary})

	case fmtJSONL:
		enc := json.NewEncoder(w)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil

	default: // text
		return renderSecretScanText(w, results, summary)
	}
}

func renderSecretScanText(w io.Writer, results []secretscan.ScanResult, summary secretscan.Summary) error {
	// Summary header
	headerStr := pterm.DefaultHeader.WithFullWidth().Sprint("Secret Scan Results")
	fmt.Fprintln(w, headerStr)

	// Summary stats
	fmt.Fprintf(w, "Projects scanned: %d\n", summary.TotalProjects)
	fmt.Fprintf(w, "Projects with findings: %d\n", summary.ProjectsWithFindings)
	fmt.Fprintf(w, "Total secrets found: %d\n", summary.TotalFindings)

	if len(summary.ByScanner) > 0 {
		fmt.Fprintln(w, "\nFindings by scanner:")
		for scanner, count := range summary.ByScanner {
			fmt.Fprintf(w, "  %s: %d\n", scanner, count)
		}
	}
	fmt.Fprintln(w)

	// Results table
	if summary.TotalFindings == 0 {
		s := pterm.DefaultSection.Sprint("No secrets found")
		fmt.Fprintln(w, s)
		return nil
	}

	tableData := pterm.TableData{
		{"Project", "Scanner", "Rule", "File", "Line", "Verified"},
	}
	for _, r := range results {
		for _, f := range r.Findings {
			verified := ""
			if f.Verified {
				verified = "YES"
			}
			line := ""
			if f.Line > 0 {
				line = fmt.Sprintf("%d", f.Line)
			}
			tableData = append(tableData, []string{
				r.PathWithNamespace,
				f.Scanner,
				f.RuleID,
				f.File,
				line,
				verified,
			})
		}
	}

	s, err := pterm.DefaultTable.
		WithHasHeader().
		WithData(tableData).
		WithLeftAlignment().
		Srender()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, s)
	return err
}
