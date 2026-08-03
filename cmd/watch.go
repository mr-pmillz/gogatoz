package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/refwatch"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	watchTarget   string
	watchBranches string
	watchInterval string
	watchNotify   string
	watchFormat   string
	watchShortCI  string
	watchBurst    int
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Continuously monitor GitLab projects for supply chain indicators",
	Long: `Poll a GitLab project's CI configuration at a regular interval.
When the configuration changes, run the analysis engine and alert on
campaign matches, critical findings, or other supply chain indicators.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(watchTarget) == "" {
			return fmt.Errorf("--target is required")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		client, err := newGitLabClient()
		if err != nil {
			return err
		}

		interval, err := time.ParseDuration(watchInterval)
		if err != nil {
			return fmt.Errorf("invalid --interval: %w", err)
		}
		if interval <= 0 {
			return fmt.Errorf("--interval must be positive")
		}
		shortLivedWindow, err := time.ParseDuration(strings.TrimSpace(watchShortCI))
		if err != nil || shortLivedWindow <= 0 {
			return fmt.Errorf("invalid --short-lived-window: %q", watchShortCI)
		}
		format := strings.ToLower(strings.TrimSpace(watchFormat))
		if format != "text" && format != "json" {
			return fmt.Errorf("invalid --format %q: expected text or json", watchFormat)
		}
		if watchBurst <= 0 {
			return fmt.Errorf("--burst-threshold must be positive")
		}

		branches := strings.Split(watchBranches, ",")
		for i := range branches {
			branches[i] = strings.TrimSpace(branches[i])
		}

		notifyURL := strings.TrimSpace(watchNotify)
		lastSHA := map[string]string{}
		lastDocs := map[string]*pipeline.Document{}
		refMonitor := refwatch.NewMonitor(refwatch.Options{
			ShortLivedWindow: shortLivedWindow,
			BurstThreshold:   watchBurst,
		}, func(checkCtx context.Context, _ string, oldSHA, newSHA string) (bool, error) {
			return client.IsCommitAncestor(checkCtx, watchTarget, oldSHA, newSHA)
		})
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		renderInfo(cmd.ErrOrStderr(), fmt.Sprintf("Watching %s (branches: %s, interval: %s)",
			watchTarget, strings.Join(branches, ","), interval))

		checkOnce := func() {
			for _, branch := range branches {
				if branch == "" {
					continue
				}
				findings := pollAndAnalyze(ctx, client, watchTarget, branch, lastSHA, lastDocs)
				if len(findings) == 0 {
					continue
				}

				alert := watchAlert{
					Time:     time.Now().UTC().Format(time.RFC3339),
					Project:  watchTarget,
					Branch:   branch,
					Findings: findings,
				}

				_ = writeWatchAlert(cmd.OutOrStdout(), alert, format)

				if notifyURL != "" {
					sendWatchNotification(notifyURL, alert)
				}
			}

			snapshot, snapshotErr := client.GetRefSnapshot(ctx, watchTarget, time.Now().UTC().Add(-shortLivedWindow))
			if snapshotErr != nil {
				renderWarning(cmd.ErrOrStderr(), fmt.Sprintf("ref monitoring failed: %v", snapshotErr))
				return
			}
			refFindings := refMonitor.Observe(ctx, convertRefSnapshot(snapshot))
			if len(refFindings) == 0 {
				return
			}
			alert := watchAlert{
				Time:     time.Now().UTC().Format(time.RFC3339),
				Project:  watchTarget,
				Findings: refFindings,
			}
			_ = writeWatchAlert(cmd.OutOrStdout(), alert, format)
			if notifyURL != "" {
				sendWatchNotification(notifyURL, alert)
			}
		}

		checkOnce()
		for {
			select {
			case <-sigCh:
				renderInfo(cmd.ErrOrStderr(), "Received signal, shutting down")
				return nil
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				checkOnce()
			}
		}
	},
}

type watchAlert struct {
	Time     string            `json:"time"`
	Project  string            `json:"project"`
	Branch   string            `json:"branch,omitempty"`
	Findings []analyze.Finding `json:"findings"`
}

func sendWatchNotification(url string, alert watchAlert) {
	body, err := json.Marshal(alert)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body)) //nolint:gosec // user-provided webhook URL
	if err != nil {
		return
	}
	resp.Body.Close()
}

func pollAndAnalyze(
	ctx context.Context,
	client *gitlabx.Client,
	projectID, branch string,
	lastSHA map[string]string,
	lastDocs map[string]*pipeline.Document,
) []analyze.Finding {
	key := projectID + ":" + branch
	previousSHA := lastSHA[key]
	f, _, err := client.GL.RepositoryFiles.GetFile(projectID, ".gitlab-ci.yml", &gitlab.GetFileOptions{
		Ref: new(branch),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil
	}

	if f.CommitID == previousSHA {
		return nil
	}

	content, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil
	}

	doc, err := pipeline.Parse(bytes.NewReader(content))
	if err != nil {
		return nil
	}
	previousDoc := lastDocs[key]
	lastSHA[key] = f.CommitID
	lastDocs[key] = doc

	findings, err := analyze.Run(doc)
	if err != nil {
		return nil
	}
	if previousDoc != nil && refwatch.ReleaseWorkflowChanged(previousDoc, doc) {
		findings = append(findings, analyze.Finding{
			ID: refwatch.ReleaseWorkflowChangedID, Severity: analyze.SeverityHigh,
			Title: "Release workflow changed", JobName: "release",
			Description: "Publishing-job configuration changed after the prior monitoring observation.",
			Evidence:    "ref=" + branch + " old_commit=" + previousSHA + " new_commit=" + f.CommitID,
		})
	}

	var critical []analyze.Finding
	for _, finding := range findings {
		if finding.Severity == analyze.SeverityCritical || finding.Severity == analyze.SeverityHigh {
			critical = append(critical, finding)
		}
	}
	return critical
}

func convertRefSnapshot(snapshot gitlabx.RefSnapshot) refwatch.Snapshot {
	converted := refwatch.Snapshot{
		ObservedAt: snapshot.ObservedAt,
		Branches:   make(map[string]refwatch.RefState, len(snapshot.Branches)),
		Tags:       make(map[string]refwatch.RefState, len(snapshot.Tags)),
	}
	for name, state := range snapshot.Branches {
		converted.Branches[name] = refwatch.RefState{
			SHA: state.SHA, CreatedAt: state.CreatedAt, HasRecentPipeline: state.HasRecentPipeline,
		}
	}
	for name, state := range snapshot.Tags {
		converted.Tags[name] = refwatch.RefState{
			SHA: state.SHA, CreatedAt: state.CreatedAt, HasRecentPipeline: state.HasRecentPipeline,
		}
	}
	return converted
}

func writeWatchAlert(w io.Writer, alert watchAlert, format string) error {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return json.NewEncoder(w).Encode(alert)
	}
	ref := alert.Branch
	if ref == "" {
		ref = "refs"
	}
	renderWarning(w, fmt.Sprintf("[%s] %s@%s: %d findings detected",
		alert.Time, alert.Project, ref, len(alert.Findings)))
	for _, finding := range alert.Findings {
		if _, err := fmt.Fprintf(w, "  [%s] %s: %s\n", finding.Severity, finding.ID, finding.Title); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(watchCmd)
	watchCmd.Flags().StringVar(&watchTarget, "target", "", "Project ID or path to monitor (required)")
	watchCmd.Flags().StringVar(&watchBranches, "branches", "main", "Comma-separated branches to monitor")
	watchCmd.Flags().StringVar(&watchInterval, "interval", "60s", "Poll interval (e.g. 30s, 5m)")
	watchCmd.Flags().StringVar(&watchNotify, "notify", "", "Webhook URL for alerts (optional)")
	watchCmd.Flags().StringVar(&watchFormat, "format", "text", "Output format: text|json")
	watchCmd.Flags().StringVar(&watchShortCI, "short-lived-window", "15m", "Maximum lifetime for alerting on a removed branch with recent CI activity")
	watchCmd.Flags().IntVar(&watchBurst, "burst-threshold", 5, "New branch and tag count per interval that triggers a burst alert")
}
