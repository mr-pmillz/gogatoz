package analyze

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

// detectDispatchTOCTOU flags risks around manual jobs or downstream triggers that can be invoked out-of-order
// or with broad scope, potentially allowing time-of-check time-of-use exploits.
//
//nolint:gocognit
func detectDispatchTOCTOU(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	// Precompute which jobs are MR-triggered (used to assess downstream consumption)
	mrProducer := map[string]bool{}
	for _, j := range doc.Jobs {
		if jobTriggersOnMR(j.Rules) || triggersOnMRViaOnly(j.Only) {
			mrProducer[j.Name] = true
		}
	}

	for _, job := range doc.Jobs {
		isManual := strings.EqualFold(job.When, "manual")
		hasTrigger := job.Trigger != nil
		if !isManual && !hasTrigger {
			continue
		}

		broad := jobRulesAllowBroad(job.Rules) || onlyIsBroad(job.Only) || workflowRulesAllowBroad(doc.Workflow.Rules)
		severity := SeverityLow
		desc := "Manual or triggered job with potentially broad scope; may be vulnerable to TOCTOU if upstream state changes."

		// If this job depends on MR-triggered producers, risk increases
		var riskyNeeds []string
		for _, n := range job.Needs {
			if mrProducer[n] {
				riskyNeeds = append(riskyNeeds, n)
			}
		}
		if len(riskyNeeds) > 0 {
			severity = SeverityMedium
			desc = "Manual/triggered job consumes outputs from MR-triggered jobs. This can enable TOCTOU and artifact poisoning across approval boundaries."
		}
		if broad {
			// escalate one level for broad scope
			if severity == SeverityLow {
				severity = SeverityMedium
			} else {
				severity = SeverityHigh
			}
		}

		// Evidence
		var evParts []string
		if isManual {
			evParts = append(evParts, "when=manual")
		}
		if hasTrigger {
			evParts = append(evParts, "trigger=true")
		}
		if len(riskyNeeds) > 0 {
			evParts = append(evParts, "needs="+strings.Join(riskyNeeds, ","))
		}
		if broad {
			evParts = append(evParts, "broad=true")
		}

		findings = append(findings, Finding{
			ID:          "DISPATCH_TOCTOU_RISK",
			Severity:    severity,
			Title:       "Manual/triggered job may be vulnerable to TOCTOU",
			Description: desc,
			Evidence:    stringutil.TruncateEvidence(strings.Join(evParts, " "), 200),
			JobName:     job.Name,
		})
	}

	return findings
}

// detectPwnRequestNuances flags deployment jobs triggered by MRs that lack protections/approvals.
func detectPwnRequestNuances(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		if job.Environment == "" {
			continue
		}
		mr := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mr {
			continue
		}
		protected := checkForkProtection(job.Rules)
		sev := SeverityHigh
		desc := "MR-triggered deployment without explicit protections/approvals. This can enable privilege escalation via Pwn Request."
		if job.AllowFailure {
			// allow_failure deployments are slightly less impactful
			sev = SeverityMedium
		}
		if protected {
			// if protections are present but weak, lower risk a bit
			sev = SeverityMedium
			desc = "MR-triggered deployment has some protection hints but may be insufficient. Review approvals and protected branch rules."
		}
		// Tagged runners increase impact
		if len(job.Tags) > 0 && sev != SeverityHigh {
			sev = SeverityHigh
		}
		findings = append(findings, Finding{
			ID:          "PWN_REQUEST_DEPLOYMENT",
			Severity:    sev,
			Title:       "MR-triggered deployment may allow privilege escalation",
			Description: desc,
			Evidence:    stringutil.TruncateEvidence("env="+job.Environment+" rules="+toJSONString(job.Rules), 200),
			JobName:     job.Name,
		})
	}
	return findings
}

// detectPrivilegedRunnerUse flags use of docker:dind or similar privileged services/images in risky contexts.
func detectPrivilegedRunnerUse(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		mr := jobTriggersOnMR(job.Rules) || triggersOnMRViaOnly(job.Only)
		if !mr {
			continue
		}
		priv := jobUsesDind(job) || strings.Contains(strings.ToLower(job.Image), "docker")
		if !priv {
			continue
		}
		sev := SeverityMedium
		desc := "MR-triggered job uses docker:dind or privileged container context. This can enable runner breakout if combined with runner misconfiguration."
		if len(job.Tags) > 0 {
			sev = SeverityHigh
		}
		findings = append(findings, Finding{
			ID:          "PRIVILEGED_RUNNER_RISK",
			Severity:    sev,
			Title:       "Privileged container context on MR-triggered job",
			Description: desc,
			Evidence:    stringutil.TruncateEvidence("image="+job.Image+" services="+strings.Join(job.Services, ","), 200),
			JobName:     job.Name,
		})
	}
	return findings
}

func jobUsesDind(job pipeline.Job) bool {
	for _, s := range job.Services {
		ls := strings.ToLower(s)
		if strings.Contains(ls, "docker:dind") || strings.Contains(ls, "-dind") || strings.Contains(ls, ":dind") || strings.Contains(ls, "docker:24") || strings.Contains(ls, "docker:25") {
			return true
		}
	}
	return false
}
