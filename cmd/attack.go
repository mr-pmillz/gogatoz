package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

const (
	payloadPwnRequest        = "pwn-request"
	payloadRor               = "ror"
	payloadRunnerOnRunner    = "runner-on-runner"
	payloadRunnerOnRunnerAlt = "runneronrunner"
	payloadNestedRunner      = "nested-runner"
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Run attack workflows against a target GitLab project",
	Long:  "Attack modes allow committing CI pipelines or other actions to validate or exploit misconfigurations.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// New: payload-only path prints YAML/JSON and exits; no token/target required
		if atkPayloadOnly {
			return runAttackPayloadOnly(cmd)
		}

		if token == "" {
			return fmt.Errorf("GitLab token is required. Provide --token or set GITLAB_TOKEN")
		}
		if strings.TrimSpace(atkTarget) == "" {
			return fmt.Errorf("--target is required (project ID or path-with-namespace)")
		}
		// Mode selection: exactly one of the attack modes (unless discovery or payload-only)
		if !atkDiscoverTags {
			modes := 0
			if atkCommitCI {
				modes++
			}
			if atkSecrets {
				modes++
			}
			if atkCleanup {
				modes++
			}
			if atkDeployKey {
				modes++
			}
			if atkAddMember {
				modes++
			}
			if atkAIInject {
				modes++
			}
			if atkInjectScript {
				modes++
			}
			if atkAutoMerge {
				modes++
			}
			if atkTamperRelease {
				modes++
			}
			if atkTamperPackage {
				modes++
			}
			if atkHarvest {
				modes++
			}
			if atkTamperTag {
				modes++
			}
			if atkLOTPInject {
				modes++
			}
			if atkRorListen {
				modes++
			}
			if atkMemoryDump {
				modes++
			}
			if atkSupplyChainWorm {
				modes++
			}
			if atkContainerEscape {
				modes++
			}
			if atkVariableInject {
				modes++
			}
			if atkC2Channel {
				modes++
			}
			if atkNpmTamper {
				modes++
			}
			if atkVaultEnum {
				modes++
			}
			if atkK8sSecrets {
				modes++
			}
			if atkDeadManSwitch {
				modes++
			}
			if atkBranchMutator {
				modes++
			}
			if atkSigstore {
				modes++
			}
			if modes != 1 {
				return fmt.Errorf("select exactly one mode: --commit-ci, --secrets, --cleanup, --deploy-key, --add-member, --ai-inject, --inject-script, --lotp-inject, --auto-merge, --tamper-release, --tamper-package, --tamper-tag, --harvest, --ror-listen, --memory-dump, --supply-chain-worm, --container-escape, --variable-inject, --c2-channel, --npm-tamper, --vault-enum, --k8s-secrets, --dead-man-switch, --branch-mutator, or --sigstore (or use --payload-only or --discover-tags)")
			}
		}

		// Build client with global knobs (reuse code style from search/enumerate)
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

		if strings.TrimSpace(atkBranch) == "" {
			atkBranch = gogatozAttack
		}

		// Dispatch to handler functions
		switch {
		case atkDiscoverTags:
			return runAttackDiscoverTags(ctx, cmd, client)
		case atkDeployKey:
			return runAttackDeployKey(ctx, cmd, client)
		case atkAddMember:
			return runAttackAddMember(ctx, cmd, client)
		case atkCleanup:
			return runAttackCleanup(ctx, cmd, client)
		case atkAIInject:
			return runAttackAIInject(ctx, cmd, client)
		case atkAutoMerge:
			return runAttackAutoMerge(ctx, cmd, client)
		case atkHarvest:
			return runAttackHarvest(ctx, cmd, client)
		case atkTamperRelease:
			return runAttackTamperRelease(ctx, cmd, client)
		case atkTamperPackage:
			return runAttackTamperPackage(ctx, cmd, client)
		case atkTamperTag:
			return runAttackTamperTag(ctx, cmd, client)
		case atkInjectScript:
			return runAttackInjectScript(ctx, cmd, client)
		case atkLOTPInject:
			return runAttackLOTPInject(ctx, cmd, client)
		case atkRorListen:
			return runAttackRorListen(ctx, cmd, client)
		case atkMemoryDump:
			return runAttackMemoryDump(ctx, cmd, client)
		case atkSupplyChainWorm:
			return runAttackSupplyChainWorm(ctx, cmd, client)
		case atkContainerEscape:
			return runAttackContainerEscape(ctx, cmd, client)
		case atkVariableInject:
			return runAttackVariableInject(ctx, cmd, client)
		case atkC2Channel:
			return runAttackC2Channel(ctx, cmd, client)
		case atkNpmTamper:
			return runAttackNpmTamper(ctx, cmd, client)
		case atkVaultEnum:
			return runAttackVaultEnum(ctx, cmd, client)
		case atkK8sSecrets:
			return runAttackK8sSecrets(ctx, cmd, client)
		case atkDeadManSwitch:
			return runAttackDeadManSwitch(ctx, cmd, client)
		case atkBranchMutator:
			return runAttackBranchMutator(ctx, cmd, client)
		case atkSigstore:
			return runAttackSigstore(ctx, cmd, client)
		case atkSecrets:
			return runAttackSecrets(ctx, cmd, client)
		default:
			// commit-ci is the default/fallthrough mode
			return runAttackCommitCI(ctx, cmd, client)
		}
	},
}
