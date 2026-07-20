package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/secretscan"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// secretScanTool is the MCP tool definition for secret scanning.
var secretScanTool = &mcp.Tool{
	Name: "secretscan_projects",
	Description: `Clone GitLab projects and scan for secrets using external tools (TruffleHog, Gitleaks, Titus).

Discovers projects matching filters, clones them locally, runs secret scanning tools, and returns findings.
Requires at least one scanner tool (trufflehog, gitleaks, or titus) installed on the host.

Supports authenticated scanning (with GitLab token) and unauthenticated scanning for public projects.
Use search_projects first to identify targets, then secretscan_projects to clone and scan them.`,
}

// --- Input / Output types ------------------------------------------------

type secretScanInput struct {
	Query        string `json:"query"          jsonschema:"Search query for project discovery"`
	Visibility   string `json:"visibility"     jsonschema:"Filter: public, internal, private"`
	PerPage      int64  `json:"per_page"       jsonschema:"Results per page (default 50)"`
	MaxPages     int64  `json:"max_pages"      jsonschema:"Max pages to fetch (0=unlimited)"`
	Scanners     string `json:"scanners"       jsonschema:"Scanners: trufflehog,gitleaks,titus or auto (default: auto)"`
	Concurrency  int    `json:"concurrency"    jsonschema:"Concurrent scanning workers (default 4)"`
	DiscardRepos bool   `json:"discard_repos"  jsonschema:"Remove repos after scanning to save disk space"`
	CloneDepth   int    `json:"clone_depth"    jsonschema:"Git clone depth (default 1, 0=full history)"`
	OutputDir    string `json:"output_dir"     jsonschema:"Directory for cloned repos (default: temp dir)"`
	Redact       bool   `json:"redact"         jsonschema:"Redact secret values in results"`
}

type secretFindingOut struct {
	Scanner     string  `json:"scanner"`
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description,omitempty"`
	File        string  `json:"file"`
	Line        int     `json:"line,omitempty"`
	Secret      string  `json:"secret,omitempty"` //nolint:gosec // scanner finding field, not a credential
	Entropy     float64 `json:"entropy,omitempty"`
	Commit      string  `json:"commit,omitempty"`
	Author      string  `json:"author,omitempty"`
	Date        string  `json:"date,omitempty"`
	Verified    bool    `json:"verified,omitempty"`
	Severity    string  `json:"severity,omitempty"`
}

type secretScanProjectOut struct {
	ProjectID         int64              `json:"project_id"`
	PathWithNamespace string             `json:"path_with_namespace"`
	WebURL            string             `json:"web_url,omitempty"`
	Scanners          []string           `json:"scanners"`
	Findings          []secretFindingOut `json:"findings,omitempty"`
	FindingsCount     int                `json:"findings_count"`
	DurationMS        int64              `json:"duration_ms"`
	Error             string             `json:"error,omitempty"`
}

type secretScanSummaryOut struct {
	TotalProjects        int            `json:"total_projects"`
	TotalFindings        int            `json:"total_findings"`
	ProjectsWithFindings int            `json:"projects_with_findings"`
	ByScanner            map[string]int `json:"by_scanner"`
}

type secretScanOutput struct {
	Results []secretScanProjectOut `json:"results"`
	Summary secretScanSummaryOut   `json:"summary"`
}

// --- Handler -------------------------------------------------------------

func (s *Server) handleSecretScan(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input secretScanInput,
) (*mcp.CallToolResult, secretScanOutput, error) {
	// Determine output directory
	outputDir := strings.TrimSpace(input.OutputDir)
	if outputDir == "" {
		dir, err := os.MkdirTemp("", "gogatoz-secretscan-*")
		if err != nil {
			return nil, secretScanOutput{}, fmt.Errorf("create temp dir: %w", err)
		}
		outputDir = dir
		// Clean up temp dir when discarding
		if input.DiscardRepos {
			defer os.RemoveAll(dir)
		}
	}

	opts := secretscan.Options{
		OutputDir:    outputDir,
		Scanners:     input.Scanners,
		Concurrency:  input.Concurrency,
		CloneDepth:   input.CloneDepth,
		DiscardRepos: input.DiscardRepos,
		Redact:       input.Redact,
		Query:        input.Query,
		Visibility:   input.Visibility,
		PerPage:      input.PerPage,
		MaxPages:     input.MaxPages,
	}

	// Extract token from the client for git clone authentication
	token := s.client.Token()

	results, err := secretscan.Run(ctx, s.client, token, opts)
	if err != nil {
		return nil, secretScanOutput{}, fmt.Errorf("secret scan failed: %w", err)
	}

	summary := secretscan.BuildSummary(results)

	out := secretScanOutput{
		Results: make([]secretScanProjectOut, len(results)),
		Summary: secretScanSummaryOut{
			TotalProjects:        summary.TotalProjects,
			TotalFindings:        summary.TotalFindings,
			ProjectsWithFindings: summary.ProjectsWithFindings,
			ByScanner:            summary.ByScanner,
		},
	}

	for i, r := range results {
		p := secretScanProjectOut{
			ProjectID:         r.GitLabProjectID,
			PathWithNamespace: r.PathWithNamespace,
			WebURL:            r.WebURL,
			Scanners:          r.Scanners,
			FindingsCount:     r.FindingsCount,
			DurationMS:        r.DurationMS,
			Error:             r.Error,
		}
		p.Findings = make([]secretFindingOut, len(r.Findings))
		for j, f := range r.Findings {
			p.Findings[j] = secretFindingOut{
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
		out.Results[i] = p
	}

	s.persistSecretScan(out)
	return nil, out, nil
}

func (s *Server) persistSecretScan(out secretScanOutput) {
	if s.store == nil {
		return
	}
	now := time.Now()
	session := &store.ScanSession{
		GitLabURL:          s.gitlabURL,
		StartedAt:          now,
		FinishedAt:         &now,
		Status:             "completed",
		SecretScanTotal:    len(out.Results),
		SecretScanFindings: out.Summary.TotalFindings,
	}
	if err := s.store.CreateSession(session); err != nil {
		return
	}
	srs := make([]store.SecretScanResult, len(out.Results))
	for i, r := range out.Results {
		sr := store.SecretScanResult{
			GitLabProjectID:   r.ProjectID,
			PathWithNamespace: r.PathWithNamespace,
			WebURL:            r.WebURL,
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
	if err := s.store.SaveSecretScanResults(session.ID, srs); err != nil {
		slog.Error("persist secret scan results failed", "error", err)
	}
}
