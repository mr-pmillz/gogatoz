package analyze

import (
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const ServiceCommandInjectionID = "SERVICE_COMMAND_INJECTION"

func detectServiceCommandInjection(doc *pipeline.Document) []Finding {
	var findings []Finding

	for _, job := range doc.Jobs {
		rawJob, ok := doc.Raw[job.Name].(map[string]any)
		if !ok {
			continue
		}
		services, ok := rawJob["services"].([]any)
		if !ok {
			continue
		}

		for _, svc := range services {
			svcMap, ok := svc.(map[string]any)
			if !ok {
				continue
			}
			if _, hasCmd := svcMap["command"]; !hasCmd {
				continue
			}

			sev := SeverityMedium
			if jobTriggersOnMR(job.Rules) {
				sev = SeverityHigh
			}

			svcName := ""
			if n, ok := svcMap["name"].(string); ok {
				svcName = n
			}

			findings = append(findings, Finding{
				ID:       ServiceCommandInjectionID,
				Severity: sev,
				Title:    "Service container command override",
				Description: fmt.Sprintf("Job '%s' overrides the command for service '%s'. "+
					"An attacker who controls the CI config can execute arbitrary code in the service container.",
					job.Name, svcName),
				Evidence: stringutil.TruncateEvidence(fmt.Sprintf("Job: %s, Service: %s", job.Name, svcName), 200),
				JobName:  job.Name,
			})
		}
	}

	return findings
}
