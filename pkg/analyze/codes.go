package analyze

import "sort"

// FindingCodeInfo provides metadata about a finding code.
// +kubebuilder:object:generate=true
type FindingCodeInfo struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	DocURL      string   `json:"docUrl,omitempty"`
	Taxonomy    Taxonomy `json:"taxonomy,omitempty"`
}

// findingCodeRegistry maps finding IDs to their metadata.
var findingCodeRegistry = map[string]FindingCodeInfo{
	"WORKFLOW_BROAD_RULES": {
		ID:          "WORKFLOW_BROAD_RULES",
		Severity:    SeverityInformational,
		Title:       "Workflow has broad rules",
		Description: "Top-level workflow rules appear broad (e.g., when: always). Ensure pipeline is gated appropriately to avoid unintended triggers.",
		Remediation: "Restrict top-level workflow rules to specific branches, tags, or pipeline sources rather than using 'when: always'; gate pipelines with protected branch or approval requirements. See: https://docs.gitlab.com/ee/ci/yaml/workflow.html",
	},
	IncludeRemoteID: {
		ID:          IncludeRemoteID,
		Severity:    SeverityHigh,
		Title:       "Remote include in pipeline",
		Description: "Pipeline includes a remote URL. If the remote is compromised or modified, your pipeline can be hijacked. Prefer project includes with pinned refs.",
		Remediation: "Avoid remote includes; prefer project includes pinned to a commit. If remote is necessary, allowlist hosts and pin exact versions. See: https://docs.gitlab.com/ee/ci/yaml/includes.html#includeremote",
	},
	"INCLUDE_PROJECT_UNPINNED": {
		ID:          "INCLUDE_PROJECT_UNPINNED",
		Severity:    SeverityHigh,
		Title:       "Unpinned project include",
		Description: "Project include without a ref pin (branch/tag/commit). Changes upstream may silently alter your pipeline.",
		Remediation: "Pin project includes to a tag or commit to prevent upstream changes from silently altering your pipeline. See: https://docs.gitlab.com/ee/ci/yaml/includes.html#syntax-for-include",
	},
	"INCLUDE_COMPONENT": {
		ID:          "INCLUDE_COMPONENT",
		Severity:    SeverityMedium,
		Title:       "CI/CD component include",
		Description: "Pipeline uses a CI/CD component. Ensure the component source is trusted and pinned.",
		Remediation: "Use trusted components and pin explicit versions; review inputs for injection risks. See: https://docs.gitlab.com/ee/ci/components/",
	},
	"SELF_HOSTED_EXPOSED": {
		ID:          "SELF_HOSTED_EXPOSED",
		Severity:    SeverityHigh,
		Title:       "Job on tagged runner with broad triggers",
		Description: "Job targets specific runner tags and is broadly triggerable (e.g., when: always or wide refs). This can enable runner takeover.",
		Remediation: "Tighten job rules/only conditions, restrict to protected branches, and limit access to sensitive runner tags. See: https://docs.gitlab.com/ee/user/project/protected_branches/ and https://docs.gitlab.com/runner/",
	},
	"MR_TAGGED_RUNNER": {
		ID:          "MR_TAGGED_RUNNER",
		Severity:    SeverityMedium,
		Title:       "MR-triggered job on tagged runner",
		Description: "Job triggers on merge_request_event (rules/only) and uses tagged runners. Ensure the job is safe for fork MRs or restrict with protected conditions/approval.",
		Remediation: "Restrict MR-triggered jobs on tagged runners to protected branches or require approvals; disable fork MR pipelines if unsafe. See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html and https://docs.gitlab.com/ee/user/project/protected_branches/",
	},
	"RISKY_REMOTE_SCRIPT": {
		ID:          "RISKY_REMOTE_SCRIPT",
		Severity:    SeverityMedium,
		Title:       "Job executes remote script content",
		Description: "Script downloads code from the network and executes it directly (e.g., curl|bash, wget|sh, PowerShell iwr|iex). This is risky unless the source is fully trusted and pinned.",
		Remediation: "Avoid piping network content into shells; vendor scripts or pin by checksum/version before execution. See: https://docs.gitlab.com/ee/ci/yaml/",
	},
	"ARTIFACTS_NO_EXPIRE": {
		ID:          "ARTIFACTS_NO_EXPIRE",
		Severity:    SeverityInformational,
		Title:       "Artifacts do not specify expire_in",
		Description: "Job defines artifacts without an expire_in. This can keep artifacts indefinitely, increasing exfiltration risk and storage cost.",
		Remediation: "Set artifacts:expire_in to a bounded period and avoid exposing sensitive artifacts. See: https://docs.gitlab.com/ee/ci/yaml/#artifacts",
	},
	"PLAINTEXT_SECRET": {
		ID:          "PLAINTEXT_SECRET",
		Severity:    SeverityMedium,
		Title:       "Suspicious plaintext variable",
		Description: "Variable name looks secret-like and contains plaintext. Consider using masked, protected variables and avoid committing secrets.",
		Remediation: "Move secrets into masked/protected CI variables or a secrets manager; rotate any exposed credentials. See: https://docs.gitlab.com/ee/ci/variables/",
	},
	"PLAINTEXT_SECRET_JOB": {
		ID:          "PLAINTEXT_SECRET_JOB",
		Severity:    SeverityMedium,
		Title:       "Suspicious plaintext variable at job level",
		Description: "Job-level variable name looks secret-like and contains plaintext.",
		Remediation: "Move secrets into masked/protected CI variables or a secrets manager; rotate any exposed credentials. See: https://docs.gitlab.com/ee/ci/variables/",
	},
	"VARIABLE_INJECTION": {
		ID:          "VARIABLE_INJECTION",
		Severity:    SeverityMedium,
		Title:       "Unsafe CI variable usage in script",
		Description: "Script references an attacker-controllable CI variable that may enable command injection if the variable content is interpreted as code.",
		Remediation: "Sanitize or avoid attacker-controllable CI variables (e.g., CI_MERGE_REQUEST_TITLE, CI_COMMIT_MESSAGE) in scripts; use fixed values or validated inputs instead of interpolating user-supplied data. See: https://docs.gitlab.com/ee/ci/variables/ and https://docs.gitlab.com/ee/ci/yaml/script.html",
	},
	"FORK_MR_UNPROTECTED": {
		ID:          "FORK_MR_UNPROTECTED",
		Severity:    SeverityMedium,
		Title:       "MR job lacks fork protection",
		Description: "MR-triggered job does not gate on fork protection (e.g., source==target check). Fork MR authors can potentially trigger this job with modified code.",
		Remediation: "Enable fork MR protections (protected branches, approvals, or disable fork MR pipelines). See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html#enable-or-disable-pipelines-for-merge-requests and https://docs.gitlab.com/ee/user/project/protected_branches/",
	},
	"FORK_SCRIPT_EXECUTION": {
		ID:          "FORK_SCRIPT_EXECUTION",
		Severity:    SeverityMedium,
		Title:       "Fork MR can modify executed repo script",
		Description: "MR-triggered job executes a repo-local script without fork protection. Fork MR authors can modify this script to inject arbitrary code.",
		Remediation: "Avoid executing repo-local scripts in MR-triggered jobs from forks. Use inline scripts, pin script checksums, or add fork protection rules (source project == target project). See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html",
	},
	"AI_PROMPT_INJECTION": {
		ID:          "AI_PROMPT_INJECTION",
		Severity:    SeverityMedium,
		Title:       "AI tool in MR-triggered job vulnerable to prompt injection",
		Description: "MR-triggered job invokes an AI tool that processes untrusted content from fork MRs, enabling prompt injection attacks.",
		Remediation: "Do not run AI code review tools on untrusted fork MR content. Isolate AI workflows to trusted branches, use read-only permissions, validate AI outputs before committing, and never pass MR descriptions or untrusted file content as prompts. See: https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation",
	},
	"ARTIFACT_POISONING_RISK": {
		ID:          "ARTIFACT_POISONING_RISK",
		Severity:    SeverityMedium,
		Title:       "Job consumes artifacts from MR-triggered sources",
		Description: "Job depends on artifacts from MR-triggered jobs. Fork MR authors can poison artifacts and compromise downstream jobs.",
		Remediation: "Avoid consuming artifacts from MR-triggered jobs in privileged downstream stages; use dependencies keyword to limit artifact scope, require approvals for artifact-producing MR pipelines, or validate artifact integrity before use. See: https://docs.gitlab.com/ee/ci/yaml/#dependencies and https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html",
	},
	"DISPATCH_TOCTOU_RISK": {
		ID:          "DISPATCH_TOCTOU_RISK",
		Severity:    SeverityMedium,
		Title:       "Manual/triggered job may be vulnerable to TOCTOU",
		Description: "Manual or trigger-dependent job may be susceptible to time-of-check-to-time-of-use (TOCTOU) attacks if upstream state can change between trigger and execution.",
		Remediation: "Constrain manual/triggered jobs and verify upstream state before use. Consider approvals and environment protections. See: https://docs.gitlab.com/ee/ci/yaml/#whenmanual and https://docs.gitlab.com/ee/ci/yaml/#needs",
	},
	"PWN_REQUEST_DEPLOYMENT": {
		ID:          "PWN_REQUEST_DEPLOYMENT",
		Severity:    SeverityHigh,
		Title:       "MR-triggered deployment may allow privilege escalation",
		Description: "MR-triggered deployment without explicit protections/approvals. This can enable privilege escalation via Pwn Request.",
		Remediation: "Protect deployments (protected environments, approvals) and restrict MR-triggered deploys. See: https://docs.gitlab.com/ee/ci/environments/protected_environments.html and https://docs.gitlab.com/ee/user/project/merge_requests/approvals/",
	},
	"PRIVILEGED_RUNNER_RISK": {
		ID:          "PRIVILEGED_RUNNER_RISK",
		Severity:    SeverityMedium,
		Title:       "Privileged container context on MR-triggered job",
		Description: "MR-triggered job uses docker:dind or privileged container context. This can enable runner breakout if combined with runner misconfiguration.",
		Remediation: "Avoid docker-in-docker or privileged context on MR-triggered jobs; prefer rootless or buildkit alternatives and hardened runners. See: https://docs.gitlab.com/ee/ci/docker/using_docker_build.html#use-docker-in-docker-workflow-with-dind and https://docs.gitlab.com/runner/security/",
	},
	"RUNNER_EXECUTOR_RISK": {
		ID:          "RUNNER_EXECUTOR_RISK",
		Severity:    SeverityCritical,
		Title:       "Job targets runners with risky executor type",
		Description: "Job targets runners using a shell or docker executor, which carries elevated risk of host compromise or container escape.",
		Remediation: "Playbook: (1) Identify which runners use shell executors via GitLab Admin > Runners. " +
			"(2) Migrate shell runners to Docker or Kubernetes executors on isolated hosts. " +
			"(3) If shell runners are required, restrict them to protected branches only. " +
			"(4) Enable runner tags to prevent MR-triggered jobs from targeting shell runners. " +
			"(5) Audit the runner host for signs of compromise (unauthorized processes, modified crontabs). " +
			"See: https://docs.gitlab.com/runner/executors/",
	},
	ScriptInjectionRiskID: {
		ID:          ScriptInjectionRiskID,
		Severity:    SeverityHigh,
		Title:       "MR job executes external repo script",
		Description: "MR-triggered job executes an external script from the repository. An attacker can modify these scripts in an MR without changing the CI config, making the attack harder to detect during code review.",
		Remediation: "Avoid executing repo-local scripts in MR-triggered jobs; use inline script commands, pin script checksums, or move scripts to a trusted project include. Add fork protection rules to prevent untrusted modifications. See: https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html",
	},
	SelfMergePossibleID: {
		ID:          SelfMergePossibleID,
		Severity:    SeverityHigh,
		Title:       "Self-merge possible (insufficient approval enforcement)",
		Description: "MR-triggered jobs are present but no branch protection or approval requirement hints were detected. An attacker may be able to self-approve and merge an MR.",
		Remediation: "Require at least 2 approvals for merge requests and enable 'Prevent approval by author' in project settings. Use CODEOWNERS to enforce reviews for CI config and scripts. See: https://docs.gitlab.com/ee/user/project/merge_requests/approvals/ and https://docs.gitlab.com/ee/user/project/codeowners/",
	},
	CachePoisoningRiskID: {
		ID:          CachePoisoningRiskID,
		Severity:    SeverityMedium,
		Title:       "MR job writes to shared cache without branch isolation",
		Description: "MR-triggered job uses a shared cache with push policy. An attacker can submit an MR that poisons the cache, affecting subsequent pipeline runs on the default branch.",
		Remediation: "Set cache policy to 'pull' for MR-triggered jobs to prevent cache writes from untrusted pipelines. Use separate cache keys per branch or pipeline source. See: https://docs.gitlab.com/ee/ci/caching/#cache-policy",
	},
	"LOTP_TOOL_EXEC": {
		ID:          "LOTP_TOOL_EXEC",
		Severity:    SeverityMedium,
		Title:       "LOTP tool in MR-triggered job enables config-file RCE",
		Description: "Job runs a Living-off-the-Pipeline tool that reads configuration from repository files. An attacker can submit an MR that weaponizes these config files to execute arbitrary code.",
		Remediation: "Restrict MR-triggered jobs that run build/lint tools to protected branches, or use fork protection rules (CI_MERGE_REQUEST_SOURCE_PROJECT_PATH == CI_MERGE_REQUEST_TARGET_PROJECT_PATH). Consider moving tool config out of the repository or validating config file integrity before execution. See: https://boostsecurityio.github.io/lotp/ and https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html",
	},
	"CACHE_KEY_INJECTION": {
		ID:          "CACHE_KEY_INJECTION",
		Severity:    SeverityMedium,
		Title:       "Cache key uses attacker-controllable CI variable",
		Description: "Cache key is derived from an attacker-controllable variable. An attacker can craft an MR to target a specific cache entry, injecting malicious content that affects other pipelines.",
		Remediation: "Avoid using attacker-controllable CI variables (e.g., CI_MERGE_REQUEST_TITLE, CI_COMMIT_MESSAGE) in cache keys. Use static keys or variables derived from pipeline source/branch that are not attacker-controllable. See: https://docs.gitlab.com/ee/ci/caching/#use-the-files-keyword-to-create-a-cache-key-based-on-specific-files",
	},
	"OIDC_TOKEN_MR_RISK": {
		ID:          "OIDC_TOKEN_MR_RISK",
		Severity:    SeverityHigh,
		Title:       "OIDC token issued in MR-triggered job",
		Description: "Job defines id_tokens and is triggered by merge request events. GitLab will issue a signed OIDC token to this job. Fork authors can trigger this job and capture the token to authenticate against cloud providers (AWS, GCP, Azure Workload Identity, etc.).",
		Remediation: "Do not issue OIDC tokens in MR-triggered jobs — fork authors can harvest these tokens to authenticate against cloud providers (AWS, GCP, Azure). Restrict id_tokens to protected branch pipelines only. See: https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html and https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html",
	},
	"TRIGGER_CHAIN_RISK": {
		ID:          "TRIGGER_CHAIN_RISK",
		Severity:    SeverityMedium,
		Title:       "Downstream trigger in MR-triggered job",
		Description: "MR-triggered job launches a downstream pipeline via trigger:. Fork authors can trigger cross-project pipelines, potentially accessing downstream secrets or resources.",
		Remediation: "Avoid triggering downstream pipelines from MR-triggered jobs. If required, ensure the downstream project restricts who can trigger pipelines and does not inherit parent secrets. Use strategy:mirror carefully and prefer strategy:depend only on protected pipelines. See: https://docs.gitlab.com/ee/ci/yaml/#trigger and https://docs.gitlab.com/ee/ci/pipelines/downstream_pipelines.html",
	},
	DebugTraceEnabledID: {
		ID:          DebugTraceEnabledID,
		Severity:    SeverityCritical,
		Title:       "CI debug trace enabled — secrets exposed in job logs",
		Description: "CI_DEBUG_TRACE or CI_DEBUG_SERVICES is enabled, which causes GitLab Runner to print every environment variable — including masked secrets — to the job log.",
		Remediation: "Playbook: (1) Remove CI_DEBUG_TRACE and CI_DEBUG_SERVICES from project and group CI/CD variables. " +
			"(2) Check pipeline logs for any runs with debug trace enabled — masked secrets are visible in those logs. " +
			"(3) Rotate any secrets that were visible in debug trace logs. " +
			"(4) Use targeted echo statements for debugging instead of full trace mode. " +
			"See: https://docs.gitlab.com/ee/ci/variables/predefined_variables.html",
	},
	UnverifiedScriptExecID: {
		ID:          UnverifiedScriptExecID,
		Severity:    SeverityHigh,
		Title:       "Unverified script execution detected",
		Description: "Script downloads or decodes content and executes it without integrity verification (checksum, GPG, cosign).",
		Remediation: "Verify downloaded scripts with sha256sum, GPG signatures, or cosign before execution. Pin URLs to exact versions and validate checksums. See: https://docs.gitlab.com/ee/ci/yaml/script.html",
	},
	UnpinnedPackageInstallID: {
		ID:          UnpinnedPackageInstallID,
		Severity:    SeverityMedium,
		Title:       "Package installed without version pin",
		Description: "Script installs a package without pinning a specific version. Supply chain attacks can inject malicious code through unpinned dependencies.",
		Remediation: "Pin all package installs to exact versions (pip install pkg==1.0, npm install pkg@1.0, gem install pkg --version 1.0, go install pkg@v1.0, apk add pkg=1.0). Use lockfiles (requirements.txt, package-lock.json, Gemfile.lock) where available. See: https://docs.gitlab.com/ee/ci/yaml/script.html",
	},
	IncludeForbiddenVersionID: {
		ID:          IncludeForbiddenVersionID,
		Severity:    SeverityMedium,
		Title:       "Include uses mutable branch ref instead of tag",
		Description: "Project include is pinned to a branch name instead of a tag or commit SHA. Branch refs are mutable and allow the upstream project to change included code without notice.",
		Remediation: "Pin project includes to a tag or commit SHA instead of a branch name. Branch refs (main, master, develop, etc.) are mutable and can be changed by the upstream project at any time. See: https://docs.gitlab.com/ee/ci/yaml/includes.html#syntax-for-include",
	},
	SecurityJobWeakenedID: {
		ID:          SecurityJobWeakenedID,
		Severity:    SeverityCritical,
		Title:       "Security job weakened",
		Description: "A security job has been weakened by setting allow_failure, when: manual, or rules with when: never. This can cause critical security scans to be skipped or ignored.",
		Remediation: "Remove allow_failure from security jobs, ensure they run automatically (not when: manual), and remove rules that disable them (when: never). Security scans should always run and block the pipeline on failure. See: https://docs.gitlab.com/ee/ci/yaml/#allow_failure and https://docs.gitlab.com/ee/ci/yaml/#when",
	},
	JobHardcodedID: {
		ID:          JobHardcodedID,
		Severity:    SeverityMedium,
		Title:       "Job defined inline instead of from include/component",
		Description: "Job is defined directly in the pipeline instead of being sourced from a shared include or component. Inline jobs bypass centralized governance and may drift from organizational standards.",
		Remediation: "Define CI jobs in shared project includes or CI/CD components to enforce consistent configuration and centralized governance. See: https://docs.gitlab.com/ee/ci/components/ and https://docs.gitlab.com/ee/ci/yaml/includes.html",
	},
	DinDDetectedID: {
		ID:          DinDDetectedID,
		Severity:    SeverityHigh,
		Title:       "Docker-in-Docker service detected",
		Description: "Job uses a Docker-in-Docker (dind) service. On shared runners running in privileged mode, this enables container escape, lateral movement, and access to secrets from other jobs on the same runner.",
		Remediation: "Replace Docker-in-Docker with a safer alternative such as Kaniko or Buildah for building container images. These tools do not require privileged mode and avoid the security risks of running a Docker daemon inside a CI container. See: https://docs.gitlab.com/ee/ci/docker/using_docker_build.html",
	},
	DinDInsecureID: {
		ID:          DinDInsecureID,
		Severity:    SeverityHigh,
		Title:       "Docker-in-Docker with insecure daemon configuration",
		Description: "Docker-in-Docker service runs with TLS disabled or uses unencrypted port 2375. This exposes the Docker daemon to network attacks and allows interception of build secrets.",
		Remediation: "Set DOCKER_TLS_CERTDIR=/certs and use port 2376 (TLS) instead of 2375. Ensure the Docker daemon is configured with TLS certificates. See: https://docs.gitlab.com/ee/ci/docker/using_docker_build.html#docker-in-docker-with-tls-enabled-in-the-docker-executor",
	},
	"IMAGE_MUTABLE_TAG": {
		ID:          "IMAGE_MUTABLE_TAG",
		Severity:    SeverityMedium,
		Title:       "Container image uses mutable tag",
		Description: "Container image uses a mutable tag (e.g., 'latest', 'dev'). Mutable tags make builds non-reproducible because the underlying image can change without notice, introducing supply chain risks.",
		Remediation: "Pin container images to specific immutable version tags (e.g., 'python:3.12.1' instead of 'python:latest'). For maximum security, pin by digest: 'image@sha256:abc123...'. See: https://docs.gitlab.com/ee/ci/yaml/#image",
	},
	"IMAGE_NOT_PINNED": {
		ID:          "IMAGE_NOT_PINNED",
		Severity:    SeverityHigh,
		Title:       "Container image not pinned by digest",
		Description: "Container image is not pinned by its SHA256 digest. Without digest pinning, a tag can be reassigned to a different image at the registry level, introducing supply chain risks.",
		Remediation: "Pin container images using their digest: 'image: registry.example.com/myimage@sha256:abc123...'. Use 'docker inspect --format={{.RepoDigests}} <image>' to find the digest. See: https://docs.gitlab.com/ee/ci/yaml/#image",
	},
	"SCRIPT_OBFUSCATION": {
		ID:          "SCRIPT_OBFUSCATION",
		Severity:    SeverityHigh,
		Title:       "Script contains obfuscated or invisible characters",
		Description: "CI/CD script contains suspicious Unicode characters (zero-width, bidirectional overrides) that can hide malicious code from human reviewers. This technique has been used in real supply chain attacks (Trojan Source, CVE-2021-42574).",
		Remediation: "Remove zero-width and bidirectional Unicode characters from CI/CD scripts. Use tools like 'cat -v' or Unicode-aware linters to detect invisible characters. Ensure all script content is visible in plain text review. See: https://trojansource.codes/",
	},
	SecretExfilHTTPID: {
		ID:          SecretExfilHTTPID,
		Severity:    SeverityCritical,
		Title:       "Environment secrets exfiltrated via HTTP",
		Description: "CI/CD job dumps environment variables (printenv, env, /proc/self/environ) and sends them to an external endpoint. This is a hallmark of supply chain exfiltration campaigns (Hades, GhostAction, Megalodon).",
		Remediation: "Playbook: (1) Remove the environment dump and HTTP POST from the CI script immediately. " +
			"(2) Rotate ALL CI/CD secrets — project variables, group variables, and any tokens referenced in the job. " +
			"(3) Audit git log for the commit that introduced this job and investigate the author. " +
			"(4) Check the target URL/IP for prior exfiltrated data if reachable. " +
			"(5) Enable protected branches and require MR approval for .gitlab-ci.yml changes. " +
			"(6) Review pipeline execution history for successful runs of this job.",
	},
	SecretExfilArtifactID: {
		ID:          SecretExfilArtifactID,
		Severity:    SeverityHigh,
		Title:       "Environment dump uploaded as CI artifact",
		Description: "CI/CD job writes environment variables to a file and uploads it as an artifact. Anyone with project read access can download the artifact and extract secrets.",
		Remediation: "Remove the environment dump from the CI script. Never upload files containing environment variables as artifacts. Audit existing artifacts for secret exposure and rotate any leaked credentials.",
	},
	ScriptEncodedPayloadID: {
		ID:          ScriptEncodedPayloadID,
		Severity:    SeverityHigh,
		Title:       "Encoded or binary payload in CI script",
		Description: "CI/CD script contains a suspicious encoded payload (base64, hex, or binary magic bytes). This technique is used to smuggle malicious binaries or obfuscated code through CI pipelines.",
		Remediation: "Review the encoded content and determine its purpose. Remove any payloads that decode to executable binaries or obfuscated shell commands. Prefer transparent, readable CI scripts.",
	},
	WhitespaceHidingID: {
		ID:          WhitespaceHidingID,
		Severity:    SeverityMedium,
		Title:       "Script hides code with excessive whitespace",
		Description: "CI/CD script line contains excessive leading whitespace (40+ spaces) pushing content off-screen in code review diffs. This technique was used in the AsyncAPI supply chain attack to hide obfuscated payloads.",
		Remediation: "Remove excessive leading whitespace from CI scripts. Ensure all script content is visible in standard code review tools. Use linters that detect abnormally long or padded lines.",
	},
	CharcodeObfuscationID: {
		ID:          CharcodeObfuscationID,
		Severity:    SeverityMedium,
		Title:       "Character-code obfuscation in CI script",
		Description: "CI/CD script constructs strings from character codes (String.fromCharCode, chr(), pack(), printf hex). This technique is used to hide C2 hostnames and malicious URLs from static analysis, as seen in the Injective SDK attack.",
		Remediation: "Replace character-code constructions with plaintext strings. If the constructed value is a URL or hostname, investigate it as a potential C2 endpoint. Review the script for data exfiltration behavior.",
	},
	SuspiciousNetworkID: {
		ID:          SuspiciousNetworkID,
		Severity:    SeverityHigh,
		Title:       "CI script contacts suspicious network target",
		Description: "CI/CD script makes HTTP requests to suspicious infrastructure: direct IP addresses, .onion domains, paste sites, file-sharing services, or known C2 relay endpoints.",
		Remediation: "Review the target URL and determine if it is legitimate. Remove connections to suspicious infrastructure. Use an allowlist of approved external hosts in CI pipelines.",
	},
	CampaignMatchID: {
		ID:          CampaignMatchID,
		Severity:    SeverityCritical,
		Title:       "CI config matches known supply chain attack campaign",
		Description: "CI/CD configuration matches the signature of a known supply chain attack campaign. This indicates the pipeline may have been compromised using techniques from documented attacks.",
		Remediation: "Playbook: (1) FREEZE pipeline execution on this project immediately. " +
			"(2) Run git diff against the last known-good CI config to identify unauthorized changes. " +
			"(3) Rotate ALL CI/CD secrets (project tokens, group tokens, deploy keys). " +
			"(4) Check recent pipeline logs for evidence of data exfiltration or credential harvesting. " +
			"(5) Review the commit author and check for account compromise indicators. " +
			"(6) Notify your security team — this matches a known attack campaign signature.",
	},
	OIDCProvenanceAnomalyID: {
		ID:          OIDCProvenanceAnomalyID,
		Severity:    SeverityMedium,
		Title:       "OIDC provenance forgeable without branch protection",
		Description: "Push/broad-triggered job with id_tokens lacks branch protection rules. Anyone with push access can forge valid OIDC provenance to authenticate against cloud providers.",
		Remediation: "Add rules:if gates that check $CI_COMMIT_REF_PROTECTED or restrict id_tokens jobs to protected branches only. Enable branch protection with required merge request approvals.",
	},
	AIConfigCredHarvesterID: {
		ID:          AIConfigCredHarvesterID,
		Severity:    SeverityMedium,
		Title:       "AI tool config credential harvester",
		Description: "CI job creates or modifies an AI tool configuration file (.cursorrules, copilot-instructions.md, etc.) that reads credential paths. This is the Miasma attack pattern — credential harvesters disguised as AI configs.",
		Remediation: "Remove the suspicious AI config file. Audit repo for unauthorized .cursorrules, copilot-instructions.md, or similar files. Review commit history for when the file was introduced.",
	},
	AIConfigPromptInjEnhancedID: {
		ID:          AIConfigPromptInjEnhancedID,
		Severity:    SeverityMedium,
		Title:       "AI tool config with external HTTP requests",
		Description: "CI job creates or modifies an AI tool configuration file that includes HTTP request patterns, enabling exfiltration of code context and developer environment data.",
		Remediation: "Remove HTTP-calling AI config files. Use .gitignore to prevent AI config files from being committed. Review and pin AI tool configurations via project policy.",
	},
	MonorepoCorrelationID: {
		ID:          MonorepoCorrelationID,
		Severity:    SeverityHigh,
		Title:       "Monorepo coordinated compromise indicator",
		Description: "Multiple projects in the same namespace show coordinated suspicious activity — identical commit messages, same author modifying CI configs, or synchronized version bumps. This pattern matches known supply chain campaigns (Injective, Hades).",
		Remediation: "Investigate the flagged commits across all affected projects. Compare CI configs with last known-good versions. Check if the author account was compromised. Rotate CI/CD secrets in all affected projects.",
	},
	DepConfusionRiskID: {
		ID:          DepConfusionRiskID,
		Severity:    SeverityHigh,
		Title:       "Dependency confusion risk detected",
		Description: "CI configuration installs packages with private-looking names (internal scopes, corp domains). An attacker can register the same name on the public registry with a higher version to hijack dependency resolution.",
		Remediation: "Pin packages to your private registry exclusively. Use npm scope registry config, pip --index-url, or GOPROXY=direct. Claim your namespace on public registries as a defensive measure. Enable package verification/signing.",
	},
	WorkflowSecretExfilID: {
		ID:          WorkflowSecretExfilID,
		Severity:    SeverityCritical,
		Title:       "Workflow secret exfiltration detected",
		Description: "A CI job dumps environment secrets and exfiltrates them via HTTP or operates in a push-triggered context that bypasses code review. Disguised job names mask the exfiltration from casual review.",
		Remediation: "Remove or disable the suspicious job immediately. Rotate all CI/CD secrets. Enable protected branches and require merge request approval for CI configuration changes. Audit git history for the commit that introduced this job.",
	},
	WorkflowArtifactExfilID: {
		ID:          WorkflowArtifactExfilID,
		Severity:    SeverityCritical,
		Title:       "Workflow artifact-based secret exfiltration detected",
		Description: "A CI job dumps environment secrets to a file and uploads it as a CI artifact without requiring an HTTP callback. Anyone with project access can download the artifact and extract secrets. This is the Hades campaign cash-out pattern.",
		Remediation: "Remove the job and delete any uploaded artifacts containing secrets. Rotate all CI/CD secrets. Set artifact expiration policies (expire_in) on all jobs. Restrict artifact download permissions.",
	},

	// --- Variable inheritance risks ---
	VarInheritanceShadowID: {
		ID:          VarInheritanceShadowID,
		Severity:    SeverityMedium,
		Title:       "Job variable shadows a protected CI/CD variable",
		Description: "A job-level YAML variable shadows a protected project or group CI/CD variable, bypassing protection controls.",
		Remediation: "Remove the job-level variable override or ensure it does not conflict with protected variables. Use variable inheritance intentionally.",
	},
	VarUnmaskedSecretID: {
		ID:          VarUnmaskedSecretID,
		Severity:    SeverityHigh,
		Title:       "CI/CD variable with secret-like name is not masked",
		Description: "A variable whose name suggests it holds a secret is not masked. The value will be visible in job logs.",
		Remediation: "Enable masking on CI/CD variables that hold secrets (Settings > CI/CD > Variables > Masked). See: https://docs.gitlab.com/ee/ci/variables/#mask-a-cicd-variable",
	},
	VarUnprotectedSecretID: {
		ID:          VarUnprotectedSecretID,
		Severity:    SeverityHigh,
		Title:       "Masked CI/CD variable is not protected",
		Description: "A masked variable is accessible from unprotected branches and MR pipelines, enabling exfiltration.",
		Remediation: "Enable protection on masked variables so they are only available on protected branches. See: https://docs.gitlab.com/ee/ci/variables/#protect-a-cicd-variable",
	},
	VarMROverrideRiskID: {
		ID:          VarMROverrideRiskID,
		Severity:    SeverityMedium,
		Title:       "MR pipeline can override unprotected variable used in script",
		Description: "An unprotected CI/CD variable is referenced in a script that runs on MR pipelines. An attacker can override it via MR pipeline variables.",
		Remediation: "Protect variables referenced in security-sensitive scripts or restrict MR pipeline access to those scripts.",
	},

	// --- Environment/deployment risks ---
	EnvUnprotectedDeployID: {
		ID:          EnvUnprotectedDeployID,
		Severity:    SeverityHigh,
		Title:       "Job deploys to unprotected environment",
		Description: "A CI job deploys to an environment with no protection rules.",
		Remediation: "Configure environment protection rules: require approvals, restrict to protected branches. See: https://docs.gitlab.com/ee/ci/environments/protected_environments.html",
	},
	EnvNoApprovalGateID: {
		ID:          EnvNoApprovalGateID,
		Severity:    SeverityMedium,
		Title:       "Production environment lacks required approvals",
		Description: "A production-tier environment has zero required approvals for deployment.",
		Remediation: "Set required_approval_count > 0 for production environments. See: https://docs.gitlab.com/ee/ci/environments/deployment_approvals.html",
	},
	EnvMRDeployRiskID: {
		ID:          EnvMRDeployRiskID,
		Severity:    SeverityHigh,
		Title:       "MR-triggered job deploys to environment",
		Description: "A merge request pipeline can trigger deployment to an environment without proper authorization.",
		Remediation: "Restrict deployment jobs to protected branches only and configure environment protection rules.",
	},
	EnvStaleDeploymentID: {
		ID:          EnvStaleDeploymentID,
		Severity:    SeverityLow,
		Title:       "Stale environment with no recent deployments",
		Description: "An environment has not been deployed to in over 90 days, potentially running outdated code.",
		Remediation: "Review stale environments and either update deployments or stop/delete unused environments.",
	},

	// --- Pages risks ---
	PagesPublicDeployID: {
		ID:          PagesPublicDeployID,
		Severity:    SeverityMedium,
		Title:       "GitLab Pages deployment detected",
		Description: "A Pages job deploys static content that may expose internal documentation, credentials, or sensitive data publicly.",
		Remediation: "Enable Pages access control, review published content, and restrict Pages deployment to protected branches only. See: https://docs.gitlab.com/ee/user/project/pages/pages_access_control.html",
	},
	PagesMRDeployRiskID: {
		ID:          PagesMRDeployRiskID,
		Severity:    SeverityHigh,
		Title:       "Pages job can be triggered from MR pipelines",
		Description: "A GitLab Pages job runs on merge request pipelines, allowing content injection via MR. An attacker can deploy arbitrary content to the project's Pages URL.",
		Remediation: "Restrict Pages deployment jobs to protected branches only using rules:if with $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH. See: https://docs.gitlab.com/ee/user/project/pages/",
	},
	PagesSensitivePathID: {
		ID:          PagesSensitivePathID,
		Severity:    SeverityMedium,
		Title:       "Pages artifacts include potentially sensitive paths",
		Description: "Pages deployment includes paths that commonly contain sensitive information such as coverage reports, API documentation, or configuration files.",
		Remediation: "Review Pages artifact paths and exclude directories containing sensitive information (coverage/, docs/api/, config/). Use .gitlab/pages/ or public/ with curated content only.",
	},

	// --- SBOM / Supply chain pinning ---
	SBOMUnpinnedImageID: {
		ID:          SBOMUnpinnedImageID,
		Severity:    SeverityMedium,
		Title:       "Container image uses mutable or missing tag",
		Description: "A container image uses ':latest' or has no tag specified, creating a supply chain risk.",
		Remediation: "Pin container images to specific version tags or digests. Use image@sha256:... for maximum reproducibility.",
	},
	SBOMNoDigestID: {
		ID:          SBOMNoDigestID,
		Severity:    SeverityLow,
		Title:       "Container image not pinned by digest",
		Description: "A container image uses a version tag but is not pinned by digest (@sha256:...). Tags are mutable.",
		Remediation: "Pin images by digest (image@sha256:...) for fully reproducible builds. See: https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
	},
	ArtifactReportInjectionID: {
		ID:          ArtifactReportInjectionID,
		Severity:    SeverityHigh,
		Title:       "Security report artifact without recognized scanner",
		Description: "Job produces security report artifacts (SARIF, dependency scanning, etc.) but does not invoke a recognized security scanner. An attacker can inject clean reports to suppress real findings.",
		Remediation: "Ensure security report artifacts are only produced by trusted, pinned scanning tools. Do not allow MR-triggered jobs to override report artifacts.",
	},
	ServiceCommandInjectionID: {
		ID:          ServiceCommandInjectionID,
		Severity:    SeverityHigh,
		Title:       "Service container command override",
		Description: "Job overrides a service container's command, which can execute arbitrary code in the service. This is especially dangerous in MR-triggered jobs where fork authors control the CI config.",
		Remediation: "Avoid overriding service container commands in CI jobs. If necessary, restrict to protected branches and review service configurations.",
	},
}

func init() {
	for id, tax := range taxonomyRegistry {
		if info, ok := findingCodeRegistry[id]; ok {
			info.Taxonomy = tax
			findingCodeRegistry[id] = info
		}
	}
}

// LookupFinding returns metadata for a finding code, or nil if unknown.
func LookupFinding(id string) *FindingCodeInfo {
	if info, ok := findingCodeRegistry[id]; ok {
		return &info
	}
	return nil
}

// AllFindings returns all registered finding codes sorted by ID.
func AllFindings() []FindingCodeInfo {
	codes := make([]FindingCodeInfo, 0, len(findingCodeRegistry))
	for _, info := range findingCodeRegistry {
		codes = append(codes, info)
	}
	sort.Slice(codes, func(i, j int) bool {
		return codes[i].ID < codes[j].ID
	})
	return codes
}

// defaultRemediation is the fallback for findings not in the registry.
const defaultRemediation = "Review and harden configuration; apply least privilege and restrict triggers/inputs."
