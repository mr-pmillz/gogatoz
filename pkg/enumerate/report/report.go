package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

// Options controls report rendering.
type Options struct {
	OnlyFindings         bool
	PrettyJSON           bool
	FilterFalsePositives bool
}

// ProjectView adapts enumerate.Result for reporting templates.
type ProjectView struct {
	Project enumerate.Result
	// Derived
	FindingCount  int
	Critical      int
	High          int
	Medium        int
	Low           int
	Informational int
}

// RunnersView provides basic runner exposure aggregation derived from findings.
type RunnersView struct {
	ProjectsWithTagged   int
	MRTagged             int
	ExposedBroad         int
	RiskyShellExecutors  int
	RiskyDockerExecutors int
}

// PipelinesView summarizes pipeline-level risks derived from findings.
type PipelinesView struct {
	ProjectsWithCI          int
	RemoteIncludes          int
	UnpinnedProjectIncludes int
	Components              int
}

// FPSummary holds false positive filtering statistics.
type FPSummary struct {
	Enabled          bool
	RawFindings      int
	FalsePositives   int
	AdjustedFindings int
	ByReason         map[string]int
}

// Summary aggregates across projects.
type Summary struct {
	Total         int
	WithFindings  int
	Findings      int
	Exploitable   int // distinct projects with at least one exploitable finding
	BySeverity    map[analyze.Severity]int
	BySeverityStr map[string]int // string-keyed view for text templates
	FP            FPSummary
}

// AttackView adapts a stored attack result for reporting templates.
type AttackView struct {
	PathWithNamespace string
	WebURL            string
	Mode              string
	Payload           string
	Branch            string
	PipelineURL       string
	PipelineID        int64
	Tags              string
	Status            string
	Error             string
	DurationMS        int64
}

// AttackSummary aggregates attack results.
type AttackSummary struct {
	Total      int
	Successful int
	Failed     int
	ByMode     map[string]int
}

// SupplyChainView aggregates supply chain risk findings.
type SupplyChainView struct {
	ExfilFindings     int `json:"exfil_findings"`
	EncodedPayloads   int `json:"encoded_payloads"`
	CampaignMatches   int `json:"campaign_matches"`
	SuspiciousNetwork int `json:"suspicious_network"`
	ObfuscationIssues int `json:"obfuscation_issues"`
	WeakProtection    int `json:"weak_protection"`
	DepConfusion      int `json:"dep_confusion"`
	AIConfigRisk      int `json:"ai_config_risk"`
	OIDCAnomaly       int `json:"oidc_anomaly"`
	TotalRisk         int `json:"total_risk"`
}

// Report root for templates.
type Report struct {
	GeneratedAt      time.Time
	Projects         []ProjectView
	Summary          Summary
	Runners          RunnersView
	Pipelines        PipelinesView
	SupplyChain      SupplyChainView `json:"supply_chain,omitempty"`
	LogFindingsTotal int
	Attacks          []AttackView
	AttackSummary    AttackSummary
	Score            *analyze.ScoreResult `json:"score,omitempty"`
}

// Build constructs a Report from raw enumeration results.
//
//nolint:gocognit // aggregation and grouping logic kept in a single pass for performance/readability
func Build(results []enumerate.Result, opts Options) Report {
	rep := Report{GeneratedAt: time.Now()}
	rep.Summary.BySeverity = map[analyze.Severity]int{
		analyze.SeverityCritical:      0,
		analyze.SeverityHigh:          0,
		analyze.SeverityMedium:        0,
		analyze.SeverityLow:           0,
		analyze.SeverityInformational: 0,
	}
	rep.Summary.BySeverityStr = map[string]int{
		"CRITICAL":      0,
		"HIGH":          0,
		"MEDIUM":        0,
		"LOW":           0,
		"INFORMATIONAL": 0,
	}

	filterFP := opts.FilterFalsePositives
	if filterFP {
		rep.Summary.FP.Enabled = true
		rep.Summary.FP.ByReason = make(map[string]int)
	}

	for _, r := range results {
		if opts.OnlyFindings && len(r.Findings) == 0 {
			continue
		}
		pv := ProjectView{Project: r}
		pv.FindingCount = len(r.Findings)
		fpCount := 0
		for _, f := range r.Findings {
			// Track FP stats
			if filterFP && f.FalsePositive {
				rep.Summary.FP.FalsePositives++
				rep.Summary.FP.ByReason[f.FalsePositiveReason]++
				fpCount++
				continue // skip FP findings from severity/infra counts
			}

			switch f.Severity {
			case analyze.SeverityCritical:
				pv.Critical++
				rep.Summary.BySeverity[analyze.SeverityCritical]++
				rep.Summary.BySeverityStr["CRITICAL"]++
			case analyze.SeverityHigh:
				pv.High++
				rep.Summary.BySeverity[analyze.SeverityHigh]++
				rep.Summary.BySeverityStr["HIGH"]++
			case analyze.SeverityMedium:
				pv.Medium++
				rep.Summary.BySeverity[analyze.SeverityMedium]++
				rep.Summary.BySeverityStr["MEDIUM"]++
			case analyze.SeverityLow:
				pv.Low++
				rep.Summary.BySeverity[analyze.SeverityLow]++
				rep.Summary.BySeverityStr["LOW"]++
			case analyze.SeverityInformational:
				pv.Informational++
				rep.Summary.BySeverity[analyze.SeverityInformational]++
				rep.Summary.BySeverityStr["INFORMATIONAL"]++
			}
			// Runners exposure heuristics via finding IDs
			id := strings.ToUpper(f.ID)
			if strings.HasPrefix(id, "SELF_HOSTED_EXPOSED") {
				rep.Runners.ExposedBroad++
				rep.Runners.ProjectsWithTagged++
			}
			if strings.HasPrefix(id, "MR_TAGGED_RUNNER") {
				rep.Runners.MRTagged++
				rep.Runners.ProjectsWithTagged++
			}
			// Pipeline risks
			if strings.HasPrefix(id, "INCLUDE_REMOTE") {
				rep.Pipelines.RemoteIncludes++
			}
			if strings.HasPrefix(id, "INCLUDE_PROJECT_UNPINNED") {
				rep.Pipelines.UnpinnedProjectIncludes++
			}
			if strings.HasPrefix(id, "INCLUDE_COMPONENT") {
				rep.Pipelines.Components++
			}
		}
		if filterFP {
			pv.FindingCount -= fpCount
		}
		if r.HasCIPipeline {
			rep.Pipelines.ProjectsWithCI++
		}
		// Aggregate runner risky executors from correlation (if present)
		if len(r.RunnerRiskyExecutors) > 0 {
			rep.Runners.RiskyShellExecutors += r.RunnerRiskyExecutors["shell"]
			rep.Runners.RiskyDockerExecutors += r.RunnerRiskyExecutors["docker"]
		}
		// Aggregate log findings count (if any)
		rep.LogFindingsTotal += r.LogFindingsCount
		rep.Projects = append(rep.Projects, pv)
		adjustedCount := pv.FindingCount
		if adjustedCount > 0 {
			rep.Summary.WithFindings++
			rep.Summary.Findings += adjustedCount
		}
		// Count distinct projects with exploitable findings
		for _, f := range r.Findings {
			if filterFP && f.FalsePositive {
				continue
			}
			if IsExploitable(f.ID) {
				rep.Summary.Exploitable++
				break
			}
		}
	}

	// Finalize FP summary
	if filterFP {
		rep.Summary.FP.RawFindings = rep.Summary.Findings + rep.Summary.FP.FalsePositives
		rep.Summary.FP.AdjustedFindings = rep.Summary.Findings
	}
	// Sort projects by findings desc, then name
	sort.Slice(rep.Projects, func(i, j int) bool {
		if rep.Projects[i].FindingCount == rep.Projects[j].FindingCount {
			return rep.Projects[i].Project.ProjectPathWithNS < rep.Projects[j].Project.ProjectPathWithNS
		}
		return rep.Projects[i].FindingCount > rep.Projects[j].FindingCount
	})
	rep.Summary.Total = len(rep.Projects)

	// Aggregate supply chain risk findings
	for _, pv := range rep.Projects {
		for _, f := range pv.Project.Findings {
			switch f.ID {
			case "SECRET_EXFIL_HTTP", "SECRET_EXFIL_ARTIFACT",
				"WORKFLOW_SECRET_EXFIL", "WORKFLOW_ARTIFACT_EXFIL":
				rep.SupplyChain.ExfilFindings++
			case "SCRIPT_ENCODED_PAYLOAD":
				rep.SupplyChain.EncodedPayloads++
			case "CAMPAIGN_MATCH":
				rep.SupplyChain.CampaignMatches++
			case "SUSPICIOUS_NETWORK_TARGET":
				rep.SupplyChain.SuspiciousNetwork++
			case "SCRIPT_OBFUSCATION", "SCRIPT_WHITESPACE_HIDING", "CHARCODE_OBFUSCATION":
				rep.SupplyChain.ObfuscationIssues++
			case "WEAK_BRANCH_PROTECTION":
				rep.SupplyChain.WeakProtection++
			case "DEP_CONFUSION_RISK":
				rep.SupplyChain.DepConfusion++
			case "AI_CONFIG_CREDENTIAL_HARVESTER", "AI_CONFIG_PROMPT_INJECTION_ENHANCED":
				rep.SupplyChain.AIConfigRisk++
			case "OIDC_PROVENANCE_ANOMALY":
				rep.SupplyChain.OIDCAnomaly++
			}
		}
	}
	rep.SupplyChain.TotalRisk = rep.SupplyChain.ExfilFindings + rep.SupplyChain.EncodedPayloads +
		rep.SupplyChain.CampaignMatches + rep.SupplyChain.SuspiciousNetwork +
		rep.SupplyChain.ObfuscationIssues + rep.SupplyChain.WeakProtection +
		rep.SupplyChain.DepConfusion + rep.SupplyChain.AIConfigRisk +
		rep.SupplyChain.OIDCAnomaly

	// Monorepo correlation: extract signals from scan metadata and run cross-project detection.
	// Uses CISummary as a proxy for CI config presence since enumerate.Result
	// does not yet carry commit message or author email.
	var monoSignals []analyze.MonorepoSignal
	for _, pv := range rep.Projects {
		hasCIFindings := false
		for _, f := range pv.Project.Findings {
			if f.ID == "CAMPAIGN_MATCH" || f.ID == "WORKFLOW_SECRET_EXFIL" || f.ID == "WORKFLOW_ARTIFACT_EXFIL" {
				hasCIFindings = true
				break
			}
		}
		monoSignals = append(monoSignals, analyze.MonorepoSignal{
			ProjectPath:     pv.Project.ProjectPathWithNS,
			CIConfigChanged: hasCIFindings,
		})
	}
	if monoFindings := analyze.DetectMonorepoCorrelation(monoSignals); len(monoFindings) > 0 {
		for range monoFindings {
			rep.SupplyChain.TotalRisk++
		}
	}

	return rep
}

// AddAttacks populates the attack report data from a slice of AttackViews.
func (r *Report) AddAttacks(attacks []AttackView) {
	r.Attacks = attacks
	r.AttackSummary = AttackSummary{
		Total:  len(attacks),
		ByMode: make(map[string]int),
	}
	for _, a := range attacks {
		r.AttackSummary.ByMode[a.Mode]++
		if a.Status == "success" {
			r.AttackSummary.Successful++
		} else {
			r.AttackSummary.Failed++
		}
	}
}

// Default text template. Similar to prior simple output, plus totals at the end.
const defaultTextTmpl = `{{- range .Projects }}{{ .Project.ProjectPathWithNS }}	{{ .Project.WebURL }}	findings={{ .FindingCount }}	{{ .Project.CISummary }}
{{- range .Project.Findings }}
  [{{ .Severity }}] {{ .ID }}: {{ .Title }}
  {{- if .JobName }}  job={{ .JobName }}{{ end }}
  {{- if .Evidence }}  evidence={{ .Evidence }}{{ end }}
  {{- if .Recommendation }}
    Recommendation: {{ .Recommendation }}{{ end }}
{{- end }}
{{- end }}

Summary: projects={{ .Summary.Total }}, with_findings={{ .Summary.WithFindings }}, findings={{ .Summary.Findings }} (CRITICAL={{ index .Summary.BySeverityStr "CRITICAL" }} HIGH={{ index .Summary.BySeverityStr "HIGH" }} MEDIUM={{ index .Summary.BySeverityStr "MEDIUM" }} LOW={{ index .Summary.BySeverityStr "LOW" }} INFORMATIONAL={{ index .Summary.BySeverityStr "INFORMATIONAL" }})
Runners: tagged_projects_est={{ .Runners.ProjectsWithTagged }}, mr_tagged={{ .Runners.MRTagged }}, exposed_broad={{ .Runners.ExposedBroad }}
Pipelines: with_ci={{ .Pipelines.ProjectsWithCI }}, remote_includes={{ .Pipelines.RemoteIncludes }}, unpinned_includes={{ .Pipelines.UnpinnedProjectIncludes }}, components={{ .Pipelines.Components }}
Logs: findings_total={{ .LogFindingsTotal }}
`

// RenderText writes a human-readable report using the default template.
func RenderText(w io.Writer, r Report, tmpl string) error {
	if strings.TrimSpace(tmpl) == "" {
		tmpl = defaultTextTmpl
	}
	t, err := template.New("enum").Parse(tmpl)
	if err != nil {
		return err
	}
	return t.Execute(w, r)
}

// RenderJSON writes a JSON report. If pretty is true, the output is indented.
func RenderJSON(w io.Writer, r Report, pretty bool) error {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(r)
}

// RenderJSONL writes JSON Lines from the raw enumerate.Result slice.
// It respects OnlyFindings option to filter out projects without findings.
func RenderJSONL(w io.Writer, results []enumerate.Result, opts Options) error {
	enc := json.NewEncoder(w)
	for _, res := range results {
		if opts.OnlyFindings && len(res.Findings) == 0 {
			continue
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	return nil
}

// MustString renders to string for testing purposes.
func MustString(r Report) string {
	var sb strings.Builder
	_ = RenderText(&sb, r, defaultTextTmpl)
	return sb.String()
}
