package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	dedupInput  string
	dedupFormat string
	dedupOutput string
)

var dedupCmd = &cobra.Command{
	Use:   "dedup",
	Short: "Deduplicate JSONL output by project ID",
	Long: `Deduplicate GoGatoZ search or enumerate JSONL output by project ID.

Reads JSONL from stdin or a file and removes duplicate entries, keeping
the first occurrence. Works with both search output ("id" field) and
enumerate output ("project_id" field).

Examples:
  # Pipe from search to enumerate via dedup
  gogatoz search --query "vuln" --format jsonl | gogatoz parse dedup | gogatoz enumerate --input -

  # Dedup a file
  gogatoz parse dedup --input all-search.jsonl --output targets.jsonl

  # Pretty-print deduped results
  gogatoz parse dedup --input all-search.jsonl`,
	RunE: runDedup,
}

func init() {
	parseCmd.AddCommand(dedupCmd)
	dedupCmd.Flags().StringVarP(&dedupInput, "input", "i", "-", "Input file path or '-' for stdin")
	dedupCmd.Flags().StringVar(&dedupFormat, "format", "", "Output format: text|json|jsonl (default: auto-detect)")
	dedupCmd.Flags().StringVarP(&dedupOutput, "output", "o", "", "Write output to file (default: stdout)")
}

// extractProjectID extracts the project ID from a parsed JSON object.
// It checks for "project_id" (enumerate output) first, then "id" (search output).
func extractProjectID(obj map[string]any) (int64, bool) {
	for _, key := range []string{"project_id", "id"} {
		v, ok := obj[key]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int64(n), true
		case int64:
			return n, true
		case json.Number:
			if i, err := n.Int64(); err == nil {
				return i, true
			}
		}
	}
	return 0, false
}

func runDedup(cmd *cobra.Command, args []string) error {
	// Open input
	var r io.Reader
	if strings.TrimSpace(dedupInput) == "" || strings.TrimSpace(dedupInput) == "-" {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Open(strings.TrimSpace(dedupInput))
		if err != nil {
			return fmt.Errorf("open --input: %w", err)
		}
		defer f.Close()
		r = f
	}

	// Read and deduplicate
	seen := map[int64]struct{}{}
	var unique []map[string]any
	var total, dupes, skipped int

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1<<20), 10<<20) // 10 MB max line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		total++
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			skipped++
			continue
		}
		pid, ok := extractProjectID(obj)
		if !ok {
			skipped++
			continue
		}
		if _, exists := seen[pid]; exists {
			dupes++
			continue
		}
		seen[pid] = struct{}{}
		unique = append(unique, obj)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	// Stats to stderr
	fmt.Fprintf(cmd.ErrOrStderr(), "Deduplicated: %d unique from %d total (%d duplicates removed", len(unique), total, dupes)
	if skipped > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), ", %d lines skipped", skipped)
	}
	fmt.Fprintln(cmd.ErrOrStderr(), ")")

	// Open output
	w := cmd.OutOrStdout()
	var closer func() error
	if strings.TrimSpace(dedupOutput) != "" {
		f, err := os.Create(strings.TrimSpace(dedupOutput))
		if err != nil {
			return fmt.Errorf("open --output: %w", err)
		}
		w = f
		closer = f.Close
	}
	defer func() {
		if closer != nil {
			_ = closer()
		}
	}()

	// Resolve format
	fmtSel := strings.ToLower(strings.TrimSpace(dedupFormat))
	if fmtSel == "" {
		if isTerminal(w) {
			fmtSel = fmtText
		} else {
			fmtSel = fmtJSONL
		}
	}

	switch fmtSel {
	case fmtJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(unique)
	case fmtJSONL:
		return writeDedupJSONL(w, unique)
	default:
		return writeDedupPTerm(w, unique)
	}
}

func writeDedupJSONL(w io.Writer, items []map[string]any) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func writeDedupPTerm(w io.Writer, items []map[string]any) error {
	if len(items) == 0 {
		renderInfo(w, "No projects after deduplication")
		return nil
	}

	// Detect input type from first item
	_, isEnum := items[0]["project_id"]

	var data pterm.TableData
	if isEnum {
		data = append(data, []string{"Project ID", "Project", "Findings", "Web URL"})
		for _, it := range items {
			findings := "0"
			if f, ok := it["findings"]; ok {
				if arr, ok := f.([]any); ok {
					findings = fmt.Sprint(len(arr))
				}
			}
			data = append(data, []string{
				formatID(it["project_id"]),
				fmt.Sprint(it["path_with_namespace"]),
				findings,
				fmt.Sprint(it["web_url"]),
			})
		}
	} else {
		data = append(data, []string{"ID", "Project", "Visibility", "Last Activity", "Web URL"})
		for _, it := range items {
			vis := fmt.Sprint(it["visibility"])
			data = append(data, []string{
				formatID(it["id"]),
				fmt.Sprint(it["path_with_namespace"]),
				vis,
				formatTimestamp(it["last_activity_at"]),
				fmt.Sprint(it["web_url"]),
			})
		}
	}

	return renderTable(w, data)
}
