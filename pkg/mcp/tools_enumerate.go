package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// enumerateTool is the MCP tool definition for CI/CD vulnerability scanning.
var enumerateTool = &mcp.Tool{
	Name: "enumerate_projects",
	Description: `Scan GitLab projects for CI/CD security vulnerabilities. Takes a list of project identifiers (from search_projects output) and analyzes their .gitlab-ci.yml configurations.

Detects: remote/unpinned includes, runner exposure, MR-triggered jobs on tagged runners, variable injection, artifact poisoning, plaintext secrets, fork MR risks, privileged runner usage, and workflow broad rules.

Returns findings with severity (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL), evidence, and remediation recommendations. Use search_projects first to find targets, then pass their IDs or paths here.`,
}

// --- Input / Output types ------------------------------------------------

type enumerateInput struct {
	Projects       []string `json:"projects"        jsonschema:"List of project IDs or path-with-namespace strings,required"`
	Concurrency    int      `json:"concurrency"     jsonschema:"Number of concurrent workers (default 8)"`
	Timeout        string   `json:"timeout"         jsonschema:"Per-project timeout as Go duration string e.g. 30s"`
	FollowIncludes bool     `json:"follow_includes" jsonschema:"Resolve CI include directives transitively"`
	IncludeDepth   int      `json:"include_depth"   jsonschema:"Max depth for include resolution (default 2)"`
	FetchProtected bool     `json:"fetch_protected" jsonschema:"Fetch protected branch names for each project"`
	FetchRunners   bool     `json:"fetch_runners"   jsonschema:"Fetch runner summary (count and executors)"`
	RunnerScope    string   `json:"runner_scope"    jsonschema:"Runner scope: project, group, or instance (default project)"`
}

type enumerateFindingOut struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Evidence       string `json:"evidence,omitempty"`
	JobName        string `json:"job_name,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

type enumerateProjectOut struct {
	ProjectID         int64                 `json:"project_id"`
	PathWithNamespace string                `json:"path_with_namespace"`
	WebURL            string                `json:"web_url"`
	DefaultBranch     string                `json:"default_branch"`
	StarCount         int64                 `json:"star_count,omitempty"`
	HasCIPipeline     bool                  `json:"has_ci_pipeline"`
	Findings          []enumerateFindingOut `json:"findings,omitempty"`
	FindingsCount     int                   `json:"findings_count"`
	ProtectedBranches []string              `json:"protected_branches,omitempty"`
	RunnersTotal      int                   `json:"runners_total,omitempty"`
	RunnersOnline     int                   `json:"runners_online,omitempty"`
	Error             string                `json:"error,omitempty"`
}

type enumerateOutput struct {
	Results      []enumerateProjectOut `json:"results"`
	TotalScanned int                   `json:"total_scanned"`
	WithFindings int                   `json:"with_findings"`
}

// --- Handler -------------------------------------------------------------

func (s *Server) handleEnumerateProjects(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input enumerateInput,
) (*mcp.CallToolResult, enumerateOutput, error) {
	if len(input.Projects) == 0 {
		return nil, enumerateOutput{}, fmt.Errorf("projects list is required and must be non-empty")
	}

	opts := enumerate.Options{
		Concurrency:    input.Concurrency,
		FollowIncludes: input.FollowIncludes,
		IncludeDepth:   input.IncludeDepth,
		FetchProtected: input.FetchProtected,
		FetchRunners:   input.FetchRunners,
		RunnerScope:    input.RunnerScope,
	}

	if input.Timeout != "" {
		d, err := time.ParseDuration(input.Timeout)
		if err != nil {
			return nil, enumerateOutput{}, fmt.Errorf("invalid timeout %q: %w", input.Timeout, err)
		}
		opts.Timeout = d
	}

	results, err := enumerate.EnumerateProjects(ctx, s.client, input.Projects, opts)
	if err != nil {
		return nil, enumerateOutput{}, fmt.Errorf("enumeration failed: %w", err)
	}

	out := enumerateOutput{
		Results:      make([]enumerateProjectOut, len(results)),
		TotalScanned: len(results),
	}
	for i, r := range results {
		p := enumerateProjectOut{
			ProjectID:         r.ProjectID,
			PathWithNamespace: r.ProjectPathWithNS,
			WebURL:            r.WebURL,
			DefaultBranch:     r.DefaultBranch,
			StarCount:         r.StarCount,
			HasCIPipeline:     r.HasCIPipeline,
			ProtectedBranches: r.ProtectedBranches,
			RunnersTotal:      r.RunnersTotal,
			RunnersOnline:     r.RunnersOnline,
			Error:             r.Error,
		}
		p.Findings = make([]enumerateFindingOut, len(r.Findings))
		for j, f := range r.Findings {
			p.Findings[j] = enumerateFindingOut{
				ID:             f.ID,
				Severity:       string(f.Severity),
				Title:          f.Title,
				Description:    f.Description,
				Evidence:       f.Evidence,
				JobName:        f.JobName,
				Recommendation: f.Recommendation,
			}
		}
		p.FindingsCount = len(r.Findings)
		if p.FindingsCount > 0 {
			out.WithFindings++
		}
		out.Results[i] = p
	}

	s.persistEnumerate(out)
	return nil, out, nil
}

func (s *Server) persistEnumerate(out enumerateOutput) {
	if s.store == nil {
		return
	}
	now := time.Now()
	session := &store.ScanSession{
		GitLabURL:    s.gitlabURL,
		StartedAt:    now,
		FinishedAt:   &now,
		Status:       "completed",
		EnumTotal:    out.TotalScanned,
		EnumFindings: out.WithFindings,
	}
	if err := s.store.CreateSession(session); err != nil {
		return
	}
	ers := make([]store.EnumerateResult, len(out.Results))
	for i, r := range out.Results {
		pbJSON, _ := json.Marshal(r.ProtectedBranches)
		er := store.EnumerateResult{
			GitLabProjectID:   r.ProjectID,
			PathWithNamespace: r.PathWithNamespace,
			WebURL:            r.WebURL,
			DefaultBranch:     r.DefaultBranch,
			StarCount:         r.StarCount,
			HasCIPipeline:     r.HasCIPipeline,
			FindingsCount:     r.FindingsCount,
			ProtectedBranches: string(pbJSON),
			RunnersTotal:      r.RunnersTotal,
			RunnersOnline:     r.RunnersOnline,
			Error:             r.Error,
		}
		er.Findings = make([]store.Finding, len(r.Findings))
		for j, f := range r.Findings {
			er.Findings[j] = store.Finding{
				FindingID:      f.ID,
				Severity:       f.Severity,
				Title:          f.Title,
				Description:    f.Description,
				Evidence:       f.Evidence,
				JobName:        f.JobName,
				Recommendation: f.Recommendation,
			}
		}
		ers[i] = er
	}
	if err := s.store.SaveEnumerateResults(session.ID, ers); err != nil {
		fmt.Fprintf(os.Stderr, "[mcp] persist enumerate results: %v\n", err)
	}
}
