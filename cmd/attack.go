package cmd

import (
	"context"
	"fmt"
	"strings"

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
			if atkDepConfusion {
				modes++
			}
			if atkRunnerVarDump {
				modes++
			}
			if atkWorkflowExfil {
				modes++
			}
			if atkCommitPrefix {
				modes++
			}
			if atkReleaseTamperPipeline {
				modes++
			}
			if modes != 1 {
				return fmt.Errorf("select exactly one mode: --commit-ci, --secrets, --cleanup, --deploy-key, --add-member, --ai-inject, --inject-script, --lotp-inject, --auto-merge, --tamper-release, --tamper-package, --tamper-tag, --harvest, --ror-listen, --memory-dump, --supply-chain-worm, --container-escape, --variable-inject, --c2-channel, --npm-tamper, --vault-enum, --k8s-secrets, --dead-man-switch, --branch-mutator, --sigstore, --dep-confusion, --runner-var-dump, --workflow-exfil, --commit-prefix, or --release-tamper-pipeline (or use --payload-only or --discover-tags)")
			}
		}

		// Build client with global knobs (reuse code style from search/enumerate)
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		client, err := newGitLabClient()
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
		case atkDepConfusion:
			return runAttackGeneratedPayload(ctx, cmd, client, "dep-confusion")
		case atkRunnerVarDump:
			return runAttackGeneratedPayload(ctx, cmd, client, "runner-var-dump")
		case atkWorkflowExfil:
			return runAttackGeneratedPayload(ctx, cmd, client, "workflow-exfil")
		case atkCommitPrefix:
			return runAttackCommitPrefix(ctx, cmd, client)
		case atkReleaseTamperPipeline:
			return runAttackGeneratedPayload(ctx, cmd, client, "release-tamper-pipeline")
		case atkSecrets:
			return runAttackSecrets(ctx, cmd, client)
		default:
			// commit-ci is the default/fallthrough mode
			return runAttackCommitCI(ctx, cmd, client)
		}
	},
}
