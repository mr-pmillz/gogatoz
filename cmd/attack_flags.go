package cmd

import "time"

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
	atkWormMonorepo    bool   // discover siblings via package manifests
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
	// Dependency confusion mode (publish to public registry with private name)
	atkDepConfusion          bool
	atkDepConfusionPackage   string // target private package name
	atkDepConfusionRegistry  string // public registry URL
	atkDepConfusionEcosystem string // npm, pip, go
	atkDepConfusionVersion   string // version to publish (default: 99.0.0)
	// Runner variable dump mode (bypass masked variable display)
	atkRunnerVarDump       bool
	atkRunnerVarDumpMethod string // procfs, printenv, strace
	atkRunnerVarDumpFilter string // regex filter for variable names
	// Impersonation
	atkImpersonateMaintainer bool
	// Workflow exfil mode (stealthy artifact-based secret exfiltration)
	atkWorkflowExfil     bool
	atkExfilDisguise     string // disguise job name (default: code-format)
	atkExfilDumpGroupVar bool   // also dump group-level variables
	// Commit prefix mode (release trigger abuse via commit message)
	atkCommitPrefix  bool
	atkPrefixValue   string // prefix (default: feat:)
	atkPrefixMessage string // commit message body
	// Release tamper pipeline mode (in-flight release artifact tampering)
	atkReleaseTamperPipeline bool
	atkRTPTag                string // release tag to target
	atkRTPArtifact           string // artifact path to tamper
	atkRTPPayload            string // payload content to prepend
	atkRTPChecksums          string // checksums file to recalculate
	// Shared co-author trailer
	atkCoAuthor string // co-authored-by trailer for commits
)

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
	attackCmd.Flags().BoolVar(&atkWormMonorepo, "monorepo-scope", false, "Discover sibling packages via manifests (npm @scope/*, go.mod, Cargo.toml)")
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
	// Dependency confusion flags
	attackCmd.Flags().BoolVar(&atkDepConfusion, "dep-confusion", false, "Publish a package to the public registry with the same name as a private package")
	attackCmd.Flags().StringVar(&atkDepConfusionPackage, "dep-confusion-package", "", "Target private package name (e.g. @acme/utils)")
	attackCmd.Flags().StringVar(&atkDepConfusionRegistry, "dep-confusion-registry", "", "Public registry URL")
	attackCmd.Flags().StringVar(&atkDepConfusionEcosystem, "dep-confusion-ecosystem", "npm", "Package ecosystem: npm, pip, go")
	attackCmd.Flags().StringVar(&atkDepConfusionVersion, "dep-confusion-version", "99.0.0", "Version to publish (should be higher than internal)")
	// Runner variable dump flags
	attackCmd.Flags().BoolVar(&atkRunnerVarDump, "runner-var-dump", false, "Dump runner environment variables bypassing masked display")
	attackCmd.Flags().StringVar(&atkRunnerVarDumpMethod, "runner-var-dump-method", "procfs", "Dump method: procfs, printenv, strace")
	attackCmd.Flags().StringVar(&atkRunnerVarDumpFilter, "runner-var-dump-filter", "", "Regex filter for variable names")
	// Impersonation flag
	attackCmd.Flags().BoolVar(&atkImpersonateMaintainer, "impersonate-maintainer", false, "Auto-populate git author from a project maintainer (stealth)")
	// Workflow exfil mode flags
	attackCmd.Flags().BoolVar(&atkWorkflowExfil, "workflow-exfil", false, "Commit a stealthy CI job that exfiltrates secrets via artifacts (Hades campaign technique)")
	attackCmd.Flags().StringVar(&atkExfilDisguise, "exfil-disguise", "", "Disguise job name (default: code-format)")
	attackCmd.Flags().BoolVar(&atkExfilDumpGroupVar, "exfil-dump-group-vars", false, "Also dump group-level CI variables")
	// Commit prefix mode flags
	attackCmd.Flags().BoolVar(&atkCommitPrefix, "commit-prefix", false, "Commit with a release-triggering prefix to abuse automated release workflows (AsyncAPI technique)")
	attackCmd.Flags().StringVar(&atkPrefixValue, "prefix", "", "Commit message prefix (default: feat:)")
	attackCmd.Flags().StringVar(&atkPrefixMessage, "prefix-message", "", "Commit message body (default: update dependency versions)")
	// Release tamper pipeline mode flags
	attackCmd.Flags().BoolVar(&atkReleaseTamperPipeline, "release-tamper-pipeline", false, "Inject a CI job to tamper with release artifacts in-flight")
	attackCmd.Flags().StringVar(&atkRTPTag, "rtp-tag", "", "Release tag to target (default: $CI_COMMIT_TAG)")
	attackCmd.Flags().StringVar(&atkRTPArtifact, "rtp-artifact", "", "Artifact path to tamper")
	attackCmd.Flags().StringVar(&atkRTPPayload, "rtp-payload", "", "Payload content to prepend to artifact")
	attackCmd.Flags().StringVar(&atkRTPChecksums, "rtp-checksums", "", "Checksums file to recalculate after tampering")
	// Shared co-author trailer
	attackCmd.Flags().StringVar(&atkCoAuthor, "co-author", "", "Co-Authored-By trailer for commits")
}
