package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	watchTarget   string
	watchBranches string
	watchInterval string
	watchNotify   string
	watchFormat   string
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

		ctx := context.Background()
		clOpts := []gitlabx.Option{gitlabx.WithRateLimit(rateRPS, rateBurst), gitlabx.WithRetry(retryMax)}
		if ua := userAgent; strings.TrimSpace(ua) != "" {
			clOpts = append(clOpts, gitlabx.WithUserAgent(ua))
		}
		clOpts = appendSOCKS5Option(clOpts)
		client, err := gitlabx.New(strings.TrimSpace(gitlabURL), token, clOpts...)
		if err != nil {
			return err
		}

		interval, err := time.ParseDuration(watchInterval)
		if err != nil {
			return fmt.Errorf("invalid --interval: %w", err)
		}

		branches := strings.Split(watchBranches, ",")
		for i := range branches {
			branches[i] = strings.TrimSpace(branches[i])
		}

		lastSHA := map[string]string{}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Watching %s (branches: %s, interval: %s)",
			watchTarget, strings.Join(branches, ","), interval))

		checkOnce := func() {
			for _, branch := range branches {
				if branch == "" {
					continue
				}
				findings := pollAndAnalyze(ctx, client, watchTarget, branch, lastSHA)
				if len(findings) == 0 {
					continue
				}
				if watchFormat == "json" {
					b, _ := json.Marshal(struct {
						Time     string            `json:"time"`
						Project  string            `json:"project"`
						Branch   string            `json:"branch"`
						Findings []analyze.Finding `json:"findings"`
					}{
						Time:     time.Now().UTC().Format(time.RFC3339),
						Project:  watchTarget,
						Branch:   branch,
						Findings: findings,
					})
					fmt.Fprintln(cmd.OutOrStdout(), string(b))
				} else {
					renderWarning(cmd.OutOrStdout(), fmt.Sprintf("[%s] %s@%s: %d findings detected",
						time.Now().Format("15:04:05"), watchTarget, branch, len(findings)))
					for _, f := range findings {
						fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s: %s\n", f.Severity, f.ID, f.Title)
					}
				}
			}
		}

		checkOnce()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				checkOnce()
			}
		}
	},
}

func pollAndAnalyze(ctx context.Context, client *gitlabx.Client, projectID, branch string, lastSHA map[string]string) []analyze.Finding {
	key := projectID + ":" + branch
	f, _, err := client.GL.RepositoryFiles.GetFile(projectID, ".gitlab-ci.yml", &gitlab.GetFileOptions{
		Ref: gitlab.Ptr(branch),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil
	}

	if f.CommitID == lastSHA[key] {
		return nil
	}
	lastSHA[key] = f.CommitID

	content, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil
	}

	doc, err := pipeline.Parse(bytes.NewReader(content))
	if err != nil {
		return nil
	}

	findings, err := analyze.Run(doc)
	if err != nil {
		return nil
	}

	var critical []analyze.Finding
	for _, finding := range findings {
		if finding.Severity == analyze.SeverityCritical || finding.Severity == analyze.SeverityHigh {
			critical = append(critical, finding)
		}
	}
	return critical
}

func init() {
	rootCmd.AddCommand(watchCmd)
	watchCmd.Flags().StringVar(&watchTarget, "target", "", "Project ID or path to monitor (required)")
	watchCmd.Flags().StringVar(&watchBranches, "branches", "main", "Comma-separated branches to monitor")
	watchCmd.Flags().StringVar(&watchInterval, "interval", "60s", "Poll interval (e.g. 30s, 5m)")
	watchCmd.Flags().StringVar(&watchNotify, "notify", "", "Webhook URL for alerts (optional)")
	watchCmd.Flags().StringVar(&watchFormat, "format", "text", "Output format: text|json")
}
