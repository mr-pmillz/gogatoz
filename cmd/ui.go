package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
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

// renderExfilSecrets prints decrypted exfil secrets as a sorted key=value table.
func renderExfilSecrets(w io.Writer, secrets map[string]string) {
	if len(secrets) == 0 {
		renderInfo(w, "no secrets found in artifact")
		return
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	data := pterm.TableData{{"Key", "Value"}}
	for _, k := range keys {
		v := secrets[k]
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
