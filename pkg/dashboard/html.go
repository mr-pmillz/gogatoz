package dashboard

import (
	"embed"
	"encoding/json"
	"html/template"
	"io"
)

//go:embed html_template.html
var htmlFS embed.FS

// HTMLData wraps Dashboard with pre-computed JSON for Chart.js templates.
type HTMLData struct {
	Dashboard
	Version         string
	RiskDistJSON    template.JS
	TopFindingsJSON template.JS
	ScorecardsJSON  template.JS
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// RenderHTML writes a self-contained HTML dashboard report.
func RenderHTML(w io.Writer, d Dashboard, ver string) error {
	data := HTMLData{
		Dashboard:       d,
		Version:         ver,
		RiskDistJSON:    template.JS(mustJSON(d.RiskDistribution)), //nolint:gosec // trusted data from internal aggregation
		TopFindingsJSON: template.JS(mustJSON(d.TopFindings)),      //nolint:gosec // trusted data from internal aggregation
		ScorecardsJSON:  template.JS(mustJSON(d.Scorecards)),       //nolint:gosec // trusted data from internal aggregation
	}

	raw, err := htmlFS.ReadFile("html_template.html")
	if err != nil {
		return err
	}

	tmpl, err := template.New("dashboard").Parse(string(raw))
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}
