package enumerate

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const (
	executorShell  = "shell"
	executorDocker = "docker"
)

// executorRiskClass returns a risk tier for the given executor type.
//
//	"shell"             → 3 (highest — direct host access)
//	"docker"            → 2 (container — potential escape)
//	"kubernetes"        → 1 (pod isolation)
//	"docker+machine"    → 0 (ephemeral)
//	"docker-autoscaler" → 0 (ephemeral)
//	anything else       → 1 (unknown defaults to medium)
func executorRiskClass(executor string) int {
	switch strings.ToLower(strings.TrimSpace(executor)) {
	case executorShell:
		return 3
	case executorDocker:
		return 2
	case "kubernetes":
		return 1
	case "docker+machine", "docker-autoscaler":
		return 0
	default:
		return 1
	}
}

// isRunnerRelatedFinding returns true if the finding ID belongs to a class
// whose severity should be influenced by runner executor type.
func isRunnerRelatedFinding(id string) bool {
	upper := strings.ToUpper(id)
	return strings.HasPrefix(upper, "SELF_HOSTED_EXPOSED") ||
		strings.HasPrefix(upper, "MR_TAGGED_RUNNER") ||
		strings.HasPrefix(upper, "PRIVILEGED_RUNNER_RISK") ||
		strings.HasPrefix(upper, "PWN_REQUEST_DEPLOYMENT") ||
		strings.HasPrefix(upper, "RUNNER_EXECUTOR_RISK")
}

// bestExecutorRisk returns the highest executor risk class across all tags
// associated with the given job. Returns -1 if no per-tag executor data is
// available for any of the job's tags.
func bestExecutorRisk(jobName string, jobTags map[string][]string, tagExecs map[string]map[string]int) int {
	tags := jobTags[jobName]
	if len(tags) == 0 || len(tagExecs) == 0 {
		return -1
	}
	best := -1
	for _, tag := range tags {
		execs, ok := tagExecs[tag]
		if !ok {
			continue
		}
		for exec := range execs {
			rc := executorRiskClass(exec)
			if rc > best {
				best = rc
			}
		}
	}
	return best
}

// bumpByRiskClass adjusts severity based on executor risk class.
//
//	riskClass >= 3 (shell):  return SeverityCritical directly (host RCE)
//	riskClass >= 2 (docker): bump by one level
//	otherwise:               no change
func bumpByRiskClass(s analyze.Severity, riskClass int) analyze.Severity {
	if riskClass >= 3 {
		return analyze.SeverityCritical
	}
	if riskClass >= 2 {
		return bumpSeverity(s)
	}
	return s
}

// adjustFindingsForRunnerRisk bumps severities for runner-related findings based
// on executor risk class derived from per-tag runner data, or falls back to the
// legacy heuristic (RunnerRiskyExecutors / RunnerTagHits) when doc is nil.
func adjustFindingsForRunnerRisk(r *Result, doc *pipeline.Document) {
	if r == nil || len(r.Findings) == 0 {
		return
	}

	// Build jobTags map: jobName → normalized tag list
	jobTags := map[string][]string{}
	if doc != nil {
		for _, j := range doc.Jobs {
			var normed []string
			for _, t := range j.Tags {
				tag := strings.ToLower(strings.TrimSpace(t))
				if tag != "" {
					normed = append(normed, tag)
				}
			}
			if len(normed) > 0 {
				jobTags[j.Name] = normed
			}
		}
	}

	for i := range r.Findings {
		if !isRunnerRelatedFinding(r.Findings[i].ID) {
			continue
		}

		maxRisk := bestExecutorRisk(r.Findings[i].JobName, jobTags, r.RunnerTagExecutors)
		if maxRisk >= 0 {
			// Per-tag executor data available — use precise risk class
			r.Findings[i].Severity = bumpByRiskClass(r.Findings[i].Severity, maxRisk)
			continue
		}

		// Fallback: legacy signals
		riskyExec := 0
		for k, v := range r.RunnerRiskyExecutors {
			lk := strings.ToLower(strings.TrimSpace(k))
			if (lk == executorShell || lk == executorDocker) && v > 0 {
				riskyExec += v
			}
		}
		hasTagHits := len(r.RunnerTagHits) > 0
		if riskyExec > 0 || hasTagHits {
			r.Findings[i].Severity = bumpSeverity(r.Findings[i].Severity)
		}
	}
}

func bumpSeverity(s analyze.Severity) analyze.Severity {
	switch s {
	case analyze.SeverityInformational:
		return analyze.SeverityLow
	case analyze.SeverityLow:
		return analyze.SeverityMedium
	case analyze.SeverityMedium:
		return analyze.SeverityHigh
	case analyze.SeverityHigh:
		return analyze.SeverityCritical
	default:
		return analyze.SeverityCritical
	}
}

// addExecutorFindings emits RUNNER_EXECUTOR_RISK findings for jobs whose tags
// map to runners with shell or docker executors.
func addExecutorFindings(r *Result, doc *pipeline.Document) {
	if r == nil || doc == nil || len(r.RunnerTagExecutors) == 0 {
		return
	}

	for _, j := range doc.Jobs {
		if len(j.Tags) == 0 {
			continue
		}

		// Collect executor counts across all of this job's tags
		execCounts := map[string]int{}
		for _, t := range j.Tags {
			tag := strings.ToLower(strings.TrimSpace(t))
			if tag == "" {
				continue
			}
			if tagMap, ok := r.RunnerTagExecutors[tag]; ok {
				for exec, cnt := range tagMap {
					execCounts[exec] += cnt
				}
			}
		}
		if len(execCounts) == 0 {
			continue
		}

		// Determine worst risk class across all executors for this job
		worstClass := -1
		for exec := range execCounts {
			rc := executorRiskClass(exec)
			if rc > worstClass {
				worstClass = rc
			}
		}

		// Only emit for riskClass >= 2 (shell or docker)
		if worstClass < 2 {
			continue
		}

		var sev analyze.Severity
		var title string
		if worstClass >= 3 {
			sev = analyze.SeverityCritical
			title = "Job targets runners with shell executor"
		} else {
			sev = analyze.SeverityMedium
			title = "Job targets runners with docker executor"
		}

		evidence := stringutil.TruncateEvidence(fmt.Sprintf("tags=%v executors=%v", j.Tags, execCounts), 200)

		r.Findings = append(r.Findings, analyze.Finding{
			ID:       "RUNNER_EXECUTOR_RISK",
			Severity: sev,
			Title:    title,
			JobName:  j.Name,
			Evidence: evidence,
		})
	}
}
