package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/notify"
	"github.com/spf13/cobra"
)

var (
	notifyInput        string
	notifyDBPath       string
	notifySessionID    uint
	notifyAppriseURL   string
	notifyAppriseTag   string
	notifyDiscordHook  string
	notifyOnlyFindings bool
	notifyDryRun       bool
)

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Send scan results to Discord via Apprise or webhook",
	Long: `Reads enumerate results from a JSONL/JSON file, SQLite database, or stdin
and sends formatted notifications to Discord via Apprise API or direct webhook.

Examples:
  # Via Apprise
  gogatoz notify --input results.jsonl --apprise-url https://apprise.example/notify/apprise

  # Via Discord webhook
  gogatoz notify --input results.jsonl --discord-webhook https://discord.com/api/webhooks/...

  # From database
  gogatoz notify --db results.sqlite3 --session 1 --apprise-url https://apprise.example/notify/apprise

  # Piped from enumerate
  gogatoz enumerate -i targets.txt --json | gogatoz notify --apprise-url https://apprise.example/notify/apprise

  # Dry run (print formatted output without sending)
  gogatoz notify --input results.jsonl --apprise-url x --dry-run`,
	RunE: runNotify,
}

func runNotify(cmd *cobra.Command, _ []string) error {
	results, err := loadNotifyResults()
	if err != nil {
		return err
	}

	if notifyOnlyFindings {
		results = filterWithFindings(results)
	}

	appriseURL := resolveNotifyFlag(notifyAppriseURL, "APPRISE_URL")
	discordHook := resolveNotifyFlag(notifyDiscordHook, "DISCORD_WEBHOOK")

	if appriseURL == "" && discordHook == "" {
		return fmt.Errorf("either --apprise-url or --discord-webhook is required")
	}

	ctx := context.Background()

	if appriseURL != "" {
		return sendApprise(ctx, cmd, results, appriseURL)
	}
	return sendDiscord(ctx, cmd, results, discordHook)
}

func sendApprise(ctx context.Context, cmd *cobra.Command, results []enumerate.Result, url string) error {
	msg := notify.FormatAppriseMarkdown(results)

	if notifyDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), msg.Body)
		return nil
	}

	sender, err := notify.NewAppriseSender(notify.AppriseOptions{
		URL: url,
		Tag: notifyAppriseTag,
	})
	if err != nil {
		return err
	}
	return sender.Send(ctx, msg)
}

func sendDiscord(ctx context.Context, cmd *cobra.Command, results []enumerate.Result, webhookURL string) error {
	msgs := notify.FormatDiscordMessages(results)

	if notifyDryRun {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		for _, m := range msgs {
			if err := enc.Encode(m.Embeds); err != nil {
				return err
			}
		}
		return nil
	}

	sender, err := notify.NewDiscordSender(notify.DiscordOptions{
		WebhookURL: webhookURL,
	})
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if err := sender.Send(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func loadNotifyResults() ([]enumerate.Result, error) {
	switch {
	case strings.TrimSpace(notifyDBPath) != "":
		results, _, err := loadFromDB(notifyDBPath, notifySessionID)
		return results, err
	case strings.TrimSpace(notifyInput) != "":
		return loadFromFile(notifyInput)
	default:
		// Try stdin
		stat, err := os.Stdin.Stat()
		if err != nil {
			return nil, fmt.Errorf("either --input or --db is required")
		}
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("either --input or --db is required (or pipe data to stdin)")
		}
		return loadFromReader(bufio.NewReader(os.Stdin))
	}
}

func loadFromReader(buf *bufio.Reader) ([]enumerate.Result, error) {
	// Peek at first non-whitespace byte to detect format
	var b byte
	var err error
	for {
		b, err = buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read input: %w", err)
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			break
		}
	}
	if err = buf.UnreadByte(); err != nil {
		return nil, fmt.Errorf("unread input: %w", err)
	}

	if b == '[' {
		var results []enumerate.Result
		if err := json.NewDecoder(buf).Decode(&results); err != nil {
			return nil, fmt.Errorf("decode JSON array: %w", err)
		}
		return results, nil
	}

	// JSONL
	var results []enumerate.Result
	scanner := bufio.NewScanner(buf)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r enumerate.Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("decode JSONL line: %w", err)
		}
		results = append(results, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read JSONL: %w", err)
	}
	return results, nil
}

func filterWithFindings(results []enumerate.Result) []enumerate.Result {
	var filtered []enumerate.Result
	for _, r := range results {
		if len(r.Findings) > 0 {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func resolveNotifyFlag(flagVal, envName string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.Flags().StringVarP(&notifyInput, "input", "i", "", "Path to JSONL or JSON file with enumerate results")
	notifyCmd.Flags().StringVar(&notifyDBPath, "db", "", "SQLite database path")
	notifyCmd.Flags().UintVar(&notifySessionID, "session", 0, "Session ID to load from database (required with --db)")
	notifyCmd.Flags().StringVar(&notifyAppriseURL, "apprise-url", "", "Apprise API URL (e.g., https://apprise.example/notify/apprise)")
	notifyCmd.Flags().StringVar(&notifyAppriseTag, "apprise-tag", "gogatoz", "Apprise routing tag")
	notifyCmd.Flags().StringVar(&notifyDiscordHook, "discord-webhook", "", "Discord webhook URL")
	notifyCmd.Flags().BoolVar(&notifyOnlyFindings, "only-findings", false, "Only include projects with findings")
	notifyCmd.Flags().BoolVar(&notifyDryRun, "dry-run", false, "Print formatted output without sending")
}
