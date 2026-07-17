package analyze

import (
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const NeedsProjectRiskID = "NEEDS_PROJECT_RISK"

func detectNeedsProjectRisk(doc *pipeline.Document) []Finding {
	var findings []Finding

	for _, job := range doc.Jobs {
		rawJob, ok := doc.Raw[job.Name].(map[string]any)
		if !ok {
			continue
		}
		needs, ok := rawJob["needs"].([]any)
		if !ok {
			continue
		}

		for _, need := range needs {
			needMap, ok := need.(map[string]any)
			if !ok {
				continue
			}
			project, hasProject := needMap["project"]
			if !hasProject {
				continue
			}

			sev := SeverityMedium
			if jobTriggersOnMR(job.Rules) {
				sev = SeverityHigh
			}

			projStr := ""
			if s, ok := project.(string); ok {
				projStr = s
			}

			findings = append(findings, Finding{
				ID:       NeedsProjectRiskID,
				Severity: sev,
				Title:    "Cross-project artifact dependency",
				Description: "Job '" + job.Name + "' pulls artifacts from external project '" +
					projStr + "' via needs:project. If the source project is compromised, " +
					"malicious artifacts will be injected into this pipeline.",
				Evidence: stringutil.TruncateEvidence("Job: "+job.Name+", Project: "+projStr, 200),
				JobName:  job.Name,
			})
		}
	}

	return findings
}
