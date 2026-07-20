package analyze

import (
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const TriggerArtifactRiskID = "TRIGGER_ARTIFACT_RISK"

func detectTriggerArtifactRisk(doc *pipeline.Document) []Finding {
	var findings []Finding

	for _, job := range doc.Jobs {
		rawJob, ok := doc.Raw[job.Name].(map[string]any)
		if !ok {
			continue
		}
		trigger, ok := rawJob["trigger"].(map[string]any)
		if !ok {
			continue
		}
		includes := triggerIncludes(trigger)
		for _, inc := range includes {
			m, ok := inc.(map[string]any)
			if !ok {
				continue
			}
			if _, hasArtifact := m["artifact"]; !hasArtifact {
				continue
			}

			sev := SeverityHigh
			if !jobTriggersOnMR(job.Rules) && !jobRulesAllowBroad(job.Rules) {
				sev = SeverityMedium
			}

			findings = append(findings, Finding{
				ID:       TriggerArtifactRiskID,
				Severity: sev,
				Title:    "Dynamic child pipeline via artifact trigger",
				Description: "Job '" + job.Name + "' triggers a child pipeline using CI config " +
					"from a build artifact. An attacker who controls the artifact content can " +
					"execute arbitrary pipeline configuration in the child project.",
				Evidence: stringutil.TruncateEvidence("Job: "+job.Name, 200),
				JobName:  job.Name,
			})
		}
	}

	return findings
}

func triggerIncludes(trigger map[string]any) []any {
	inc, ok := trigger["include"]
	if !ok {
		return nil
	}
	switch v := inc.(type) {
	case []any:
		return v
	case map[string]any:
		return []any{v}
	default:
		return nil
	}
}
