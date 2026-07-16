package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	mcpserver "github.com/mr-pmillz/gogatoz/pkg/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the GoGatoZ MCP server (stdio transport)",
	Long: `Starts a Model Context Protocol server over stdin/stdout, exposing search
and enumerate tools for GitLab CI/CD security scanning.

Intended for use with Claude Code or other MCP-compatible clients.
Requires GITLAB_TOKEN environment variable. Optionally set GITLAB_URL
(defaults to https://gitlab.com).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("GITLAB_TOKEN is required for MCP server")
		}
		base := strings.TrimSpace(gitlabURL)
		if base == "" {
			base = "https://gitlab.com"
		}

		client, err := newGitLabClient()
		if err != nil {
			return fmt.Errorf("create GitLab client: %w", err)
		}

		if cliStore != nil && dbPath != "" {
			slog.Info("result storage enabled", "path", dbPath)
		}

		slog.Info("starting MCP server", "gitlab", base)

		srv := mcpserver.New(client, cliStore, base)
		return srv.Run(cmd.Context())
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
