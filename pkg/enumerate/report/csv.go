package report

import (
	"encoding/csv"
	"io"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

// RenderCSV writes findings as CSV rows suitable for spreadsheet or SIEM import.
// Columns: project, web_url, severity, finding_id, title, job, evidence, recommendation
func RenderCSV(w io.Writer, results []enumerate.Result) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"project", "web_url", "severity", "finding_id",
		"title", "job", "evidence", "recommendation",
	}); err != nil {
		return err
	}

	for _, r := range results {
		for _, f := range r.Findings {
			if err := cw.Write([]string{
				r.ProjectPathWithNS,
				r.WebURL,
				string(f.Severity),
				f.ID,
				f.Title,
				f.JobName,
				f.Evidence,
				f.Recommendation,
			}); err != nil {
				return err
			}
		}
	}
	return cw.Error()
}
