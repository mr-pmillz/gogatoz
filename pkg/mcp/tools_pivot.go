package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/pivot"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

var pivotTool = &mcp.Tool{
	Name: "pivot_scan",
	Description: `Automated lateral movement via CI/CD secrets exfiltration.

Enumerates projects, identifies exploitable CI/CD vulnerabilities, attacks with
secrets exfiltration via HTTP callback, harvests tokens, and pivots to discover
additional access using newly found credentials.

Requires external_url (reachable from CI runners) for non-dry-run mode.
Use dry_run to enumerate and identify exploitable targets without attacking.`,
}

type pivotInput struct {
	Targets        []string `json:"targets"         jsonschema:"Project IDs or paths (required),required"`
	Groups         []string `json:"groups"          jsonschema:"Group IDs to expand"`
	ExternalURL    string   `json:"external_url"    jsonschema:"URL reachable from CI runners for callback"`
	ListenAddr     string   `json:"listen_addr"     jsonschema:"Callback server listen address (default :9443)"`
	MaxDepth       int      `json:"max_depth"       jsonschema:"Maximum pivot depth (default 3)"`
	MaxTargets     int      `json:"max_targets"     jsonschema:"Maximum total projects to attack (default 50)"`
	MaxCredentials int      `json:"max_credentials" jsonschema:"Maximum credentials to harvest (default 20)"`
	Timeout        string   `json:"timeout"         jsonschema:"Overall timeout (default 30m)"`
	Concurrency    int      `json:"concurrency"     jsonschema:"Attack worker count (default 4)"`
	DryRun         bool     `json:"dry_run"         jsonschema:"Enumerate only, show exploitable targets"`
	Cleanup        bool     `json:"cleanup"         jsonschema:"Delete attack branches after harvest"`
	Branch         string   `json:"branch"          jsonschema:"Branch name base (default gogatoz-pivot)"`
	FollowIncludes bool     `json:"follow_includes" jsonschema:"Resolve CI include directives transitively"`
	FetchRunners   bool     `json:"fetch_runners"   jsonschema:"Fetch runner info for severity correlation"`
}

type pivotOutput struct {
	Status             string           `json:"status"`
	Error              string           `json:"error,omitempty"`
	ProjectsEnumerated int              `json:"projects_enumerated"`
	ExploitableTargets int              `json:"exploitable_targets"`
	ProjectsAttacked   int              `json:"projects_attacked"`
	CredentialsFound   int              `json:"credentials_found"`
	CredentialsValid   int              `json:"credentials_valid"`
	MaxDepthReached    int              `json:"max_depth_reached"`
	DurationMS         int64            `json:"duration_ms"`
	Credentials        []credentialInfo `json:"credentials,omitempty"`
}

type credentialInfo struct {
	TokenType       string `json:"token_type"`
	SourceKey       string `json:"source_key"`
	SourceProjectID int64  `json:"source_project_id"`
	Depth           int    `json:"depth"`
	Username        string `json:"username"`
	IsValid         bool   `json:"is_valid"`
}

func (s *Server) handlePivotScan(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input pivotInput,
) (*mcp.CallToolResult, pivotOutput, error) {
	if len(input.Targets) == 0 && len(input.Groups) == 0 {
		return nil, pivotOutput{}, fmt.Errorf("targets or groups required")
	}
	if !input.DryRun && strings.TrimSpace(input.ExternalURL) == "" {
		return nil, pivotOutput{}, fmt.Errorf("external_url required for non-dry-run mode")
	}

	timeout := 30 * time.Minute
	if input.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(input.Timeout)
		if err != nil {
			return nil, pivotOutput{}, fmt.Errorf("invalid timeout: %w", err)
		}
	}

	opts := pivot.Options{
		InitialTargets:    input.Targets,
		GroupTargets:      input.Groups,
		MaxDepth:          input.MaxDepth,
		MaxTargets:        input.MaxTargets,
		MaxCredentials:    input.MaxCredentials,
		Timeout:           timeout,
		AttackConcurrency: input.Concurrency,
		AttackBranch:      input.Branch,
		ListenAddr:        input.ListenAddr,
		ExternalURL:       input.ExternalURL,
		FollowIncludes:    input.FollowIncludes,
		FetchRunners:      input.FetchRunners,
		DryRun:            input.DryRun,
		Cleanup:           input.Cleanup,
	}

	orch, err := pivot.NewOrchestrator(s.gitlabURL, s.client.Token(), opts)
	if err != nil {
		return nil, pivotOutput{Status: statusError, Error: err.Error()}, nil
	}

	stats, err := orch.Run(ctx)
	if err != nil {
		return nil, pivotOutput{Status: statusError, Error: err.Error()}, nil
	}

	// Build credential info (no raw tokens)
	var creds []credentialInfo
	for _, c := range orch.Credentials().All() {
		if c.Depth == 0 {
			continue
		}
		creds = append(creds, credentialInfo{
			TokenType:       c.TokenType,
			SourceKey:       c.SourceKey,
			SourceProjectID: c.SourceProjectID,
			Depth:           c.Depth,
			Username:        c.Username,
			IsValid:         c.IsValid,
		})
	}

	out := pivotOutput{
		Status:             "success",
		ProjectsEnumerated: stats.ProjectsEnumerated,
		ExploitableTargets: stats.ExploitableTargets,
		ProjectsAttacked:   stats.ProjectsAttacked,
		CredentialsFound:   stats.CredentialsFound,
		CredentialsValid:   stats.CredentialsValid,
		MaxDepthReached:    stats.MaxDepthReached,
		DurationMS:         stats.Duration.Milliseconds(),
		Credentials:        creds,
	}

	// Persist to store
	if s.store != nil {
		s.persistPivot(orch, stats)
	}

	return nil, out, nil
}

func (s *Server) persistPivot(orch *pivot.Orchestrator, stats *pivot.PivotStats) {
	session := &store.ScanSession{
		GitLabURL: s.gitlabURL,
		StartedAt: time.Now().Add(-stats.Duration),
		Status:    "completed",
	}
	if err := s.store.CreateSession(session); err != nil {
		return
	}

	pivotSess := &store.PivotSession{
		SessionID:          session.ID,
		MaxDepthReached:    stats.MaxDepthReached,
		ProjectsEnumerated: stats.ProjectsEnumerated,
		ProjectsAttacked:   stats.ProjectsAttacked,
		CredentialsFound:   stats.CredentialsFound,
		CredentialsValid:   stats.CredentialsValid,
		DurationMS:         stats.Duration.Milliseconds(),
		Status:             "completed",
	}
	if err := s.store.SavePivotSession(pivotSess); err != nil {
		fmt.Fprintf(os.Stderr, "[mcp] persist pivot session: %v\n", err)
	}
}
