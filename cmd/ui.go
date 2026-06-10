package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"golang.org/x/term"
)

// isTerminal returns true if the given writer is a terminal (TTY).
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		fd := f.Fd()
		return term.IsTerminal(int(fd)) //nolint:gosec // fd is a valid file descriptor, overflow is not a concern
	}
	return false
}

// renderTable builds a pterm table from data rows and writes it to w.
// The first row is treated as the header.
func renderTable(w io.Writer, data pterm.TableData) error {
	s, err := pterm.DefaultTable.
		WithHasHeader().
		WithData(data).
		WithLeftAlignment().
		Srender()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, s)
	return err
}

// renderSuccess writes a success-styled message to w.
func renderSuccess(w io.Writer, msg string) {
	s := pterm.Success.Sprint(msg)
	fmt.Fprintln(w, s)
}

// renderError writes an error-styled message to w.
func renderError(w io.Writer, msg string) {
	s := pterm.Error.Sprint(msg)
	fmt.Fprintln(w, s)
}

// renderInfo writes an info-styled message to w.
func renderInfo(w io.Writer, msg string) {
	s := pterm.Info.Sprint(msg)
	fmt.Fprintln(w, s)
}

// renderWarning writes a warning-styled message to w.
func renderWarning(w io.Writer, msg string) {
	s := pterm.Warning.Sprint(msg)
	fmt.Fprintln(w, s)
}

// gitlabBuiltinPrefixes lists GitLab CI predefined variable prefixes that are
// purely metadata and not useful as credentials. Variables matching these
// prefixes are hidden by default unless their name also contains a secret
// indicator (see secretIndicators) or they appear in gitlabBuiltinExact.
var gitlabBuiltinPrefixes = []string{
	"CI_COMMIT_",
	"CI_BUILD_",
	"CI_JOB_",
	"CI_MERGE_REQUEST_",
	"CI_NODE_",
	"CI_PIPELINE_",
	"CI_PROJECT_",
	"CI_RUNNER_",
	"CI_SERVER_",
	"CI_ENVIRONMENT_",
	"CI_KUBERNETES_",
	"CI_RELEASE_",
	"CI_TEMPLATE_",
	"CI_API_",
	"CI_PAGES_",
	"GITLAB_USER_",
	"FF_",
}

// gitlabBuiltinExact lists exact variable names that are GitLab CI metadata
// or common OS variables with no credential value.
var gitlabBuiltinExact = map[string]struct{}{
	"CI_BUILDS_DIR": {}, "CI_CONCURRENT_ID": {}, "CI_CONCURRENT_PROJECT_ID": {},
	"CI_CONFIG_PATH": {}, "CI_DEBUG_SERVICES": {}, "CI_DEBUG_TRACE": {},
	"CI_DEFAULT_BRANCH": {}, "CI_DISPOSABLE_ENVIRONMENT": {}, "CI_SHARED_ENVIRONMENT": {},
	"CI_GITLAB_FIPS_MODE": {}, "CI_HAS_OPEN_REQUIREMENTS": {}, "CI_OPEN_MERGE_REQUESTS": {},
	"CI_REPOSITORY_URL": {}, "CI_REGISTRY_IMAGE": {}, "CI_REGISTRY": {},
	"GITLAB_CI": {}, "GITLAB_ENV": {}, "GITLAB_FEATURES": {},
	// OS / runner environment
	"HOME": {}, "PATH": {}, "PWD": {}, "OLDPWD": {}, "SHELL": {},
	"TERM": {}, "USER": {}, "LOGNAME": {}, "HOSTNAME": {}, "SHLVL": {},
	"LS_COLORS": {}, "LANG": {}, "COLORTERM": {}, "MAIL": {},
	"XDG_RUNTIME_DIR": {}, "DBUS_SESSION_BUS_ADDRESS": {},
}

// secretIndicators are substrings that, when found in a variable name,
// mark it as potentially interesting regardless of prefix.
var secretIndicators = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "KEY",
	"AUTH", "CRED", "PRIVATE", "JWT", "APIKEY", "API_KEY",
}

// filterBuiltinVars removes well-known GitLab CI metadata and OS variables
// from the map, keeping only variables that are likely to be credentials or
// user-defined. Returns a new map; the original is not modified.
func filterBuiltinVars(secrets map[string]string) map[string]string {
	out := make(map[string]string, len(secrets))
	for k, v := range secrets {
		upper := strings.ToUpper(k)

		// Keep if the name contains a secret indicator.
		interesting := false
		for _, ind := range secretIndicators {
			if strings.Contains(upper, ind) {
				interesting = true
				break
			}
		}
		if interesting {
			out[k] = v
			continue
		}

		// Hide if exact match in the boring set.
		if _, boring := gitlabBuiltinExact[k]; boring {
			continue
		}

		// Hide if it matches a known CI metadata prefix.
		builtIn := false
		for _, pfx := range gitlabBuiltinPrefixes {
			if strings.HasPrefix(upper, pfx) {
				builtIn = true
				break
			}
		}
		if builtIn {
			continue
		}

		out[k] = v
	}
	return out
}

// renderExfilSecrets prints decrypted exfil secrets as a sorted key=value table.
// Pass showAll=true to include GitLab CI built-in/OS variables.
func renderExfilSecrets(w io.Writer, secrets map[string]string, showAll bool) {
	if len(secrets) == 0 {
		renderInfo(w, "no secrets found in artifact")
		return
	}
	displayed := secrets
	if !showAll {
		displayed = filterBuiltinVars(secrets)
		hidden := len(secrets) - len(displayed)
		if hidden > 0 {
			renderInfo(w, fmt.Sprintf("filtered %d built-in CI/OS variables (use --all-vars to show all)", hidden))
		}
	}
	if len(displayed) == 0 {
		renderInfo(w, "no non-builtin secrets found in artifact")
		return
	}
	keys := make([]string, 0, len(displayed))
	for k := range displayed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	data := pterm.TableData{{"Key", "Value"}}
	for _, k := range keys {
		v := displayed[k]
		if len(v) > 120 {
			v = v[:120] + "..."
		}
		data = append(data, []string{k, v})
	}
	_ = renderTable(w, data)
}

// formatTimestamp formats a timestamp string for table display.
func formatTimestamp(ts any) string {
	switch v := ts.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Format("2006-01-02")
		}
		if len(v) > 10 {
			return v[:10]
		}
		return v
	default:
		return fmt.Sprint(v)
	}
}

// formatID formats a project ID (float64 from JSON) as a string.
func formatID(id any) string {
	switch v := id.(type) {
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return fmt.Sprint(v)
	}
}
