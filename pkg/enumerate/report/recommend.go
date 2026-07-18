package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

// Recommendation represents an actionable attack vector synthesized from
// enumeration findings across all scanned projects.
type Recommendation struct {
	Category   string   `json:"category"`
	Risk       string   `json:"risk"`
	Summary    string   `json:"summary"`
	Command    string   `json:"command,omitempty"`
	Projects   []string `json:"projects"`
	Confidence string   `json:"confidence"`
}

type recRule struct {
	category   string
	risk       string
	summary    string
	command    string
	confidence string
	findingIDs []string
}

var recRules = []recRule{
	{
		category:   "CI Injection",
		risk:       "CRITICAL",
		summary:    "Self-hosted runners exposed to MR pipelines — attacker can execute code on runner host via CI commit",
		command:    "gogatoz attack --commit-ci --target %s --payload secrets --tags shell_executor",
		confidence: "high",
		findingIDs: []string{"SELF_HOSTED_EXPOSED", "MR_TAGGED_RUNNER"},
	},
	{
		category:   "Pwn Request",
		risk:       "HIGH",
		summary:    "Fork-enabled project with MR-triggered jobs on self-hosted runners — Pwn Request attack possible",
		command:    "gogatoz attack --commit-ci --target %s --payload pwn-request --tags shell_executor",
		confidence: "high",
		findingIDs: []string{"FORK_MR_SELF_HOSTED", "PWN_REQUEST_DEPLOYMENT"},
	},
	{
		category:   "Secrets Exfiltration",
		risk:       "HIGH",
		summary:    "Plaintext secrets or weak variable protection — exfiltrate via artifact dump",
		command:    "gogatoz attack --secrets --target %s --method artifact",
		confidence: "high",
		findingIDs: []string{"PLAINTEXT_SECRET", "VARIABLE_INJECTION"},
	},
	{
		category:   "Lateral Movement",
		risk:       "HIGH",
		summary:    "Cross-project includes or trigger chains enable lateral movement across projects",
		command:    "gogatoz pivot --target %s --max-depth 2",
		confidence: "medium",
		findingIDs: []string{"TRIGGER_CHAIN_RISK", "INCLUDE_REMOTE_CACHED", "NEEDS_PROJECT_RISK"},
	},
	{
		category:   "Supply Chain",
		risk:       "HIGH",
		summary:    "Cache poisoning, dependency confusion, or artifact injection enables supply chain attacks",
		command:    "gogatoz attack --commit-ci --target %s --payload cache-poison",
		confidence: "medium",
		findingIDs: []string{"CACHE_POISONING_RISK", "CACHE_KEY_INJECTION", "DEPENDENCY_CONFUSION", "ARTIFACT_REPORT_INJECTION"},
	},
	{
		category:   "Persistence",
		risk:       "MEDIUM",
		summary:    "Deploy key or member addition possible for persistent access",
		command:    "gogatoz attack --deploy-key --target %s",
		confidence: "medium",
		findingIDs: []string{"SELF_HOSTED_EXPOSED", "RUNNER_EXECUTOR_RISK"},
	},
}

// GenerateRecommendations analyzes aggregate findings across all results and
// generates actionable attack recommendations with suggested gogatoz commands.
func GenerateRecommendations(results []enumerate.Result) []Recommendation {
	// Build index: findingID -> list of projects
	findingProjects := map[string][]string{}
	for _, r := range results {
		for _, f := range r.Findings {
			if f.FalsePositive {
				continue
			}
			findingProjects[f.ID] = appendUnique(findingProjects[f.ID], r.ProjectPathWithNS)
		}
	}

	var recs []Recommendation
	for _, rule := range recRules {
		var projects []string
		for _, fid := range rule.findingIDs {
			projects = appendUniqueSlice(projects, findingProjects[fid])
		}
		if len(projects) == 0 {
			continue
		}
		cmd := rule.command
		if strings.Contains(cmd, "%s") {
			cmd = fmt.Sprintf(cmd, projects[0])
			if len(projects) > 1 {
				cmd += fmt.Sprintf("  # ... and %d more projects", len(projects)-1)
			}
		}
		recs = append(recs, Recommendation{
			Category:   rule.category,
			Risk:       rule.risk,
			Summary:    rule.summary,
			Command:    cmd,
			Projects:   projects,
			Confidence: rule.confidence,
		})
	}
	return recs
}

func appendUnique(slice []string, val string) []string {
	if slices.Contains(slice, val) {
		return slice
	}
	return append(slice, val)
}

func appendUniqueSlice(dst, src []string) []string {
	for _, s := range src {
		dst = appendUnique(dst, s)
	}
	return dst
}
