package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// parseTags splits a comma-separated tag string into a slice.
func parseTags(s string) []string {
	var tags []string
	if t := strings.TrimSpace(s); t != "" {
		for tag := range strings.SplitSeq(t, ",") {
			if v := strings.TrimSpace(tag); v != "" {
				tags = append(tags, v)
			}
		}
	}
	return tags
}

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
		slog.Warn("pipeline wait failed", "error", err)
		return
	}
	if pipelineID > 0 {
		out.PipelineID = pipelineID
		url := fmt.Sprintf("%s/%s/-/pipelines/%d", strings.TrimSuffix(s.gitlabURL, "/"), input.Target, pipelineID)
		out.PipelineURL = url
		slog.Info("pipeline created", "url", url)
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
		slog.Error("persist attack session failed", "error", err)
		return
	}
	ar := store.AttackResult{
		GitLabProjectID:   0,
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
	if err := s.store.SaveAttackResults(session.ID, []store.AttackResult{ar}); err != nil {
		slog.Error("persist attack results failed", "error", err)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
