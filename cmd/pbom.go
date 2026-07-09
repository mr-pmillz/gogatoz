package cmd

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pbom"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	pbomProject       string
	pbomRef           string
	pbomOutput        string
	pbomFormat        string
	pbomFollowIncl    bool
	pbomIncludeDepth  int
	pbomAllowRemote   bool
	pbomRemoteAllow   string
	pbomRemoteMaxB    int64
	pbomRemoteTimeout string
)

var pbomCmd = &cobra.Command{
	Use:   "pbom",
	Short: "Generate Pipeline Bill of Materials for a project",
	Long: `Generate a Pipeline Bill of Materials (PBOM) that inventories all container
images and CI include references used in a GitLab project's CI/CD pipeline.

Output formats:
  json       Native PBOM JSON (default)
  cyclonedx  CycloneDX 1.5 SBOM (JSON)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(pbomProject) == "" {
			return fmt.Errorf("--project is required")
		}
		if token == "" && !noToken {
			return fmt.Errorf("GitLab token is required. Provide --token, set GITLAB_TOKEN, or use --no-token for unauthenticated access")
		}

		ctx := context.Background()

		// Build GitLab client (same pattern as enumerate).
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

		// Fetch project metadata.
		proj, _, err := client.GL.Projects.GetProject(strings.TrimSpace(pbomProject), nil, gitlab.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("get project %q: %w", pbomProject, err)
		}

		refToUse := strings.TrimSpace(pbomRef)
		if refToUse == "" {
			refToUse = proj.DefaultBranch
		}
		if refToUse == "" {
			return fmt.Errorf("project %q has no default branch; specify --ref", pbomProject)
		}

		// Fetch and parse .gitlab-ci.yml.
		refStr := refToUse
		file, _, err := client.GL.RepositoryFiles.GetFile(proj.ID, ".gitlab-ci.yml", &gitlab.GetFileOptions{Ref: &refStr}, gitlab.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("get .gitlab-ci.yml for %q (ref %s): %w", pbomProject, refToUse, err)
		}

		decoded, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			return fmt.Errorf("decode ci file: %w", err)
		}

		ciDoc, err := pipeline.Parse(strings.NewReader(string(decoded)))
		if err != nil {
			return fmt.Errorf("parse ci: %w", err)
		}

		// Optionally resolve includes.
		if pbomFollowIncl && len(ciDoc.Includes) > 0 {
			var remoteTO time.Duration
			if s := strings.TrimSpace(pbomRemoteTimeout); s != "" {
				if d, e := time.ParseDuration(s); e != nil {
					return fmt.Errorf("invalid --remote-timeout: %w", e)
				} else {
					remoteTO = d
				}
			}
			var allow []string
			if s := strings.TrimSpace(pbomRemoteAllow); s != "" {
				for h := range strings.SplitSeq(s, ",") {
					if h = strings.TrimSpace(h); h != "" {
						allow = append(allow, h)
					}
				}
			}
			merged, ierr := pipeline.ResolveIncludesWithOptions(ctx, client, proj.ID, refToUse, ciDoc, pbomIncludeDepth, pipeline.ResolveOptions{
				AllowRemote:      pbomAllowRemote,
				RemoteAllowHosts: allow,
				RemoteMaxBytes:   pbomRemoteMaxB,
				RemoteTimeout:    remoteTO,
			})
			if ierr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: include resolution: %v\n", ierr)
			}
			if merged != nil {
				ciDoc = merged
			}
		}

		// Generate PBOM.
		gen := pbom.NewGenerator(proj.PathWithNamespace, proj.ID, proj.WebURL, refToUse)
		result := gen.Generate(ciDoc)

		// Determine output destination.
		w := cmd.OutOrStdout()
		if p := strings.TrimSpace(pbomOutput); p != "" {
			f, ferr := os.Create(p)
			if ferr != nil {
				return fmt.Errorf("create output file: %w", ferr)
			}
			defer f.Close()
			w = f
		}

		// Encode output.
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")

		fmtSel := strings.ToLower(strings.TrimSpace(pbomFormat))
		switch fmtSel {
		case "cyclonedx", "cdx":
			cdx := result.ToCycloneDX(version)
			if err := enc.Encode(cdx); err != nil {
				return fmt.Errorf("encode cyclonedx: %w", err)
			}
		default:
			if err := enc.Encode(result); err != nil {
				return fmt.Errorf("encode pbom: %w", err)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(pbomCmd)
	pbomCmd.Flags().StringVar(&pbomProject, "project", "", "Project ID or path-with-namespace (required)")
	pbomCmd.Flags().StringVar(&pbomRef, "ref", "", "Git ref to scan (default: project's default branch)")
	pbomCmd.Flags().StringVarP(&pbomOutput, "output", "o", "", "Output file path (default: stdout)")
	pbomCmd.Flags().StringVarP(&pbomFormat, "format", "f", "json", "Output format: json | cyclonedx")
	pbomCmd.Flags().BoolVar(&pbomFollowIncl, "follow-includes", true, "Resolve includes transitively")
	pbomCmd.Flags().IntVar(&pbomIncludeDepth, "include-depth", 2, "Depth for include resolution")
	pbomCmd.Flags().BoolVar(&pbomAllowRemote, "allow-remote-includes", false, "Allow resolving remote includes")
	pbomCmd.Flags().StringVar(&pbomRemoteAllow, "remote-allowlist", "", "Comma-separated host allowlist for remote includes")
	pbomCmd.Flags().Int64Var(&pbomRemoteMaxB, "remote-max-bytes", 1<<20, "Max bytes per remote include (default 1MiB)")
	pbomCmd.Flags().StringVar(&pbomRemoteTimeout, "remote-timeout", "10s", "Timeout per remote include fetch")
}
