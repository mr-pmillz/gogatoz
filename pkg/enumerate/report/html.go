package report

import (
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"sort"
)

//go:embed html_template.html
var htmlTemplateFS embed.FS

// HTMLData wraps Report with pre-computed JSON for Chart.js templates.
type HTMLData struct {
	Report
	SeverityJSON       template.JS
	TypeCountsJSON     template.JS
	InfraJSON          template.JS
	FPSummaryJSON      template.JS
	Version            string
	AllFindings        []FlatFinding
	ExploitableEntries []ExploitableEntry
	ExploitableCount   int
	HasAttacks         bool
	HasFPFilter        bool
}

// FlatFinding is a denormalized finding with its parent project path,
// suitable for rendering in a flat table.
type FlatFinding struct {
	Severity       string
	ID             string
	Project        string
	WebURL         string
	Title          string
	JobName        string
	Evidence       string
	Recommendation string
}

// typeCount pairs a finding ID with its occurrence count.
type typeCount struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

// infraJSON is the data structure for the infrastructure chart.
type infraJSON struct {
	Runners   RunnersView   `json:"runners"`
	Pipelines PipelinesView `json:"pipelines"`
}

const badgeSecondary = "bg-secondary"

var htmlFuncMap = template.FuncMap{
	"severityBadge": func(s string) string {
		switch s {
		case "CRITICAL":
			return "bg-purple text-white"
		case "HIGH":
			return "bg-danger"
		case "MEDIUM":
			return "bg-warning text-dark"
		case "LOW":
			return badgeSecondary
		case "INFORMATIONAL":
			return "bg-info text-dark"
		default:
			return badgeSecondary
		}
	},
	"statusBadge": func(s string) string {
		switch s {
		case "success":
			return "bg-success"
		case "error":
			return "bg-danger"
		default:
			return badgeSecondary
		}
	},
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func computeTypeCounts(r Report) []typeCount {
	counts := map[string]int{}
	for _, pv := range r.Projects {
		for _, f := range pv.Project.Findings {
			counts[f.ID]++
		}
	}
	result := make([]typeCount, 0, len(counts))
	for id, c := range counts {
		result = append(result, typeCount{ID: id, Count: c})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
}

func flattenFindings(r Report) []FlatFinding {
	var out []FlatFinding
	for _, pv := range r.Projects {
		for _, f := range pv.Project.Findings {
			out = append(out, FlatFinding{
				Severity:       string(f.Severity),
				ID:             f.ID,
				Project:        pv.Project.ProjectPathWithNS,
				WebURL:         pv.Project.WebURL,
				Title:          f.Title,
				JobName:        f.JobName,
				Evidence:       f.Evidence,
				Recommendation: f.Recommendation,
			})
		}
	}
	return out
}

func buildExploitableEntries(r Report) []ExploitableEntry {
	var out []ExploitableEntry
	for _, pv := range r.Projects {
		projectTags := ResolveTags(pv.Project.RunnerTagHits, "")
		for _, f := range pv.Project.Findings {
			if !IsExploitable(f.ID) {
				continue
			}
			tags := projectTags
			if tags == "" {
				tags = ResolveTags(nil, f.Evidence)
			}
			cmd := buildAttackCommand(f.ID, pv.Project.ProjectPathWithNS, tags)
			if cmd == "" {
				continue
			}
			out = append(out, ExploitableEntry{
				Severity: string(f.Severity),
				Project:  pv.Project.ProjectPathWithNS,
				WebURL:   pv.Project.WebURL,
				ID:       f.ID,
				Title:    f.Title,
				Command:  cmd,
			})
		}
	}
	return out
}

// RenderHTML writes a self-contained HTML report with charts and DataTables.
func RenderHTML(w io.Writer, r Report, ver string) error {
	raw, err := htmlTemplateFS.ReadFile("html_template.html")
	if err != nil {
		return err
	}
	t, err := template.New("html").Funcs(htmlFuncMap).Parse(string(raw))
	if err != nil {
		return err
	}
	entries := buildExploitableEntries(r)
	data := HTMLData{
		Report:         r,
		SeverityJSON:   template.JS(mustJSON(r.Summary.BySeverityStr)), //nolint:gosec // trusted data from internal aggregation
		TypeCountsJSON: template.JS(mustJSON(computeTypeCounts(r))),    //nolint:gosec // trusted data from internal aggregation
		InfraJSON: template.JS(mustJSON(infraJSON{ //nolint:gosec // trusted data from internal aggregation
			Runners:   r.Runners,
			Pipelines: r.Pipelines,
		})),
		FPSummaryJSON:      template.JS(mustJSON(r.Summary.FP)), //nolint:gosec // trusted data from internal aggregation
		Version:            ver,
		AllFindings:        flattenFindings(r),
		ExploitableEntries: entries,
		ExploitableCount:   r.Summary.Exploitable,
		HasAttacks:         len(r.Attacks) > 0,
		HasFPFilter:        r.Summary.FP.Enabled,
	}
	return t.Execute(w, data)
}
