package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
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
		tok := strings.TrimSpace(token)
		if tok == "" {
			return fmt.Errorf("GITLAB_TOKEN is required for MCP server")
		}
		base := strings.TrimSpace(gitlabURL)
		if base == "" {
			base = "https://gitlab.com"
		}

		clOpts := []gitlabx.Option{
			gitlabx.WithRateLimit(rateRPS, rateBurst),
			gitlabx.WithRetry(retryMax),
		}
		if ua := strings.TrimSpace(userAgent); ua != "" {
			clOpts = append(clOpts, gitlabx.WithUserAgent(ua))
		}
		// HTTP pooling/timeouts
		var idleTO, tlsTO, expectTO, reqTO time.Duration
		if s := strings.TrimSpace(httpIdleTimeout); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid --http-idle-timeout: %w", err)
			}
			idleTO = d
		}
		if s := strings.TrimSpace(httpTLSTimeout); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid --http-tls-timeout: %w", err)
			}
			tlsTO = d
		}
		if s := strings.TrimSpace(httpExpectTimeout); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid --http-expect-timeout: %w", err)
			}
			expectTO = d
		}
		if s := strings.TrimSpace(httpRequestTimeout); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid --http-req-timeout: %w", err)
			}
			reqTO = d
		}
		if httpMaxIdle > 0 || httpMaxIdlePerHost > 0 {
			clOpts = append(clOpts, gitlabx.WithHTTPPool(httpMaxIdle, httpMaxIdlePerHost))
		}
		if idleTO > 0 || tlsTO > 0 || expectTO > 0 || reqTO > 0 {
			clOpts = append(clOpts, gitlabx.WithHTTPTimeouts(idleTO, tlsTO, expectTO, reqTO))
		}
		// TLS options
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

		client, err := gitlabx.New(base, tok, clOpts...)
		if err != nil {
			return fmt.Errorf("create GitLab client: %w", err)
		}

		if cliStore != nil && dbPath != "" {
			fmt.Fprintf(os.Stderr, "[mcp] result storage: %s\n", dbPath)
		}

		fmt.Fprintf(os.Stderr, "[mcp] starting MCP server (gitlab=%s)\n", base)

		srv := mcpserver.New(client, cliStore, base)
		return srv.Run(cmd.Context())
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
