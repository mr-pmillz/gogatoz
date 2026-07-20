package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/secretscan"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// persistSearchResults saves search output to the CLI store.
// Non-fatal: logs to stderr on success, silently skips on error.
func persistSearchResults(results []map[string]any, base string) {
	if cliStore == nil {
		return
	}
	now := time.Now()
	session := &store.ScanSession{
		GitLabURL:   base,
		StartedAt:   now,
		FinishedAt:  &now,
		Status:      "completed",
		SearchTotal: len(results),
	}
	if err := cliStore.CreateSession(session); err != nil {
		return
	}
	srs := make([]store.SearchResult, 0, len(results))
	for _, m := range results {
		sr := store.SearchResult{
			GitLabProjectID:   toInt64(m["id"]),
			PathWithNamespace: fmt.Sprint(m["path_with_namespace"]),
			WebURL:            fmt.Sprint(m["web_url"]),
			Visibility:        fmt.Sprint(m["visibility"]),
			DefaultBranch:     fmt.Sprint(m["default_branch"]),
			StarCount:         toInt64(m["star_count"]),
		}
		srs = append(srs, sr)
	}
	if err := cliStore.SaveSearchResults(session.ID, srs); err != nil {
		return
	}
	slog.Info("session saved", "session_id", session.ID, "search_results", len(srs))
}

// persistEnumerateResults saves enumerate output to the CLI store.
// Non-fatal: logs to stderr on success, silently skips on error.
func persistEnumerateResults(results []enumerate.Result, base string) {
	if cliStore == nil {
		return
	}
	now := time.Now()
	withFindings := 0
	for _, r := range results {
		if len(r.Findings) > 0 {
			withFindings++
		}
	}
	session := &store.ScanSession{
		GitLabURL:    base,
		StartedAt:    now,
		FinishedAt:   &now,
		Status:       "completed",
		EnumTotal:    len(results),
		EnumFindings: withFindings,
	}
	if err := cliStore.CreateSession(session); err != nil {
		return
	}
	ers := make([]store.EnumerateResult, len(results))
	for i, r := range results {
		pbJSON, _ := json.Marshal(r.ProtectedBranches)
		er := store.EnumerateResult{
			GitLabProjectID:   r.ProjectID,
			PathWithNamespace: r.ProjectPathWithNS,
			WebURL:            r.WebURL,
			DefaultBranch:     r.DefaultBranch,
			StarCount:         r.StarCount,
			HasCIPipeline:     r.HasCIPipeline,
			FindingsCount:     len(r.Findings),
			ProtectedBranches: string(pbJSON),
			RunnersTotal:      r.RunnersTotal,
			RunnersOnline:     r.RunnersOnline,
			DurationMS:        r.DurationMS,
			Error:             r.Error,
		}
		er.Findings = make([]store.Finding, len(r.Findings))
		for j, f := range r.Findings {
			er.Findings[j] = store.Finding{
				FindingID:           f.ID,
				Severity:            string(f.Severity),
				Title:               f.Title,
				Description:         f.Description,
				Evidence:            f.Evidence,
				JobName:             f.JobName,
				Recommendation:      f.Recommendation,
				FalsePositive:       f.FalsePositive,
				FalsePositiveReason: f.FalsePositiveReason,
			}
		}
		ers[i] = er
	}
	if err := cliStore.SaveEnumerateResults(session.ID, ers); err != nil {
		return
	}
	slog.Info("session saved", "session_id", session.ID, "enumerate_results", len(ers), "with_findings", withFindings)
}

// persistSecretScanResults saves secret scan output to the CLI store.
// Non-fatal: logs to stderr on success, silently skips on error.
func persistSecretScanResults(results []secretscan.ScanResult, base string) {
	if cliStore == nil {
		return
	}
	now := time.Now()
	withFindings := 0
	totalFindings := 0
	for _, r := range results {
		if r.FindingsCount > 0 {
			withFindings++
			totalFindings += r.FindingsCount
		}
	}
	session := &store.ScanSession{
		GitLabURL:          base,
		StartedAt:          now,
		FinishedAt:         &now,
		Status:             "completed",
		SecretScanTotal:    len(results),
		SecretScanFindings: totalFindings,
	}
	if err := cliStore.CreateSession(session); err != nil {
		return
	}
	srs := make([]store.SecretScanResult, len(results))
	for i, r := range results {
		sr := store.SecretScanResult{
			GitLabProjectID:   r.GitLabProjectID,
			PathWithNamespace: r.PathWithNamespace,
			WebURL:            r.WebURL,
			ClonePath:         r.ClonePath,
			Scanners:          strings.Join(r.Scanners, ","),
			FindingsCount:     r.FindingsCount,
			DurationMS:        r.DurationMS,
			Error:             r.Error,
		}
		sr.SecretFindings = make([]store.SecretFinding, len(r.Findings))
		for j, f := range r.Findings {
			sr.SecretFindings[j] = store.SecretFinding{
				Scanner:     f.Scanner,
				RuleID:      f.RuleID,
				Description: f.Description,
				File:        f.File,
				Line:        f.Line,
				Secret:      f.Secret,
				Entropy:     f.Entropy,
				Commit:      f.Commit,
				Author:      f.Author,
				Date:        f.Date,
				Verified:    f.Verified,
				Severity:    f.Severity,
			}
		}
		srs[i] = sr
	}
	if err := cliStore.SaveSecretScanResults(session.ID, srs); err != nil {
		return
	}
	slog.Info("session saved", "session_id", session.ID, "secret_scan_results", len(srs), "with_findings", withFindings)
}

// persistAttackExfil saves a secrets-mode attack result and its decrypted exfil secrets to the
// CLI store. Non-fatal: logs to stderr on success, silently skips if the store is unavailable.
func persistAttackExfil(gitlabURL, projectPath string, gitlabProjectID int64, webURL, branch, pipelineURL string, pipelineID, jobID int64, secrets map[string]string) {
	if cliStore == nil {
		return
	}
	now := time.Now()
	session := &store.ScanSession{
		GitLabURL:     gitlabURL,
		StartedAt:     now,
		FinishedAt:    &now,
		Status:        "completed",
		AttackTotal:   1,
		AttackSuccess: 1,
	}
	if err := cliStore.CreateSession(session); err != nil {
		return
	}
	ar := &store.AttackResult{
		GitLabProjectID:   gitlabProjectID,
		PathWithNamespace: projectPath,
		WebURL:            webURL,
		Mode:              "secrets",
		Branch:            branch,
		PipelineURL:       pipelineURL,
		PipelineID:        pipelineID,
		Status:            "success",
	}
	if err := cliStore.SaveAttackResult(session.ID, ar); err != nil {
		return
	}
	if len(secrets) == 0 {
		slog.Info("session saved", "session_id", session.ID, "attack_result_id", ar.ID, "secrets", 0)
		return
	}
	secs := make([]store.AttackExfilSecret, 0, len(secrets))
	for k, v := range secrets {
		secs = append(secs, store.AttackExfilSecret{Key: k, Value: v})
	}
	if err := cliStore.SaveAttackExfilSecrets(ar.ID, secs); err != nil {
		slog.Warn("attack result saved but secrets write failed", "session_id", session.ID, "error", err)
		return
	}
	slog.Info("session saved", "session_id", session.ID, "attack_result_id", ar.ID, "exfil_secrets", len(secs))
}

// toInt64 extracts an int64 from a map value that may be int, int64, float64, or string.
func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	default:
		return 0
	}
}
