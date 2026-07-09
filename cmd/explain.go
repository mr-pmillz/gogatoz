package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/spf13/cobra"
)

var (
	explainJSON bool
	explainList bool
	explainAll  bool
)

var explainCmd = &cobra.Command{
	Use:   "explain [FINDING-ID]",
	Short: "Show detailed information about a finding code",
	Long: `Display detailed information about a GoGatoZ finding code, including
its severity, description, remediation guidance, and documentation link.

Use --list to see all available finding codes, or --all for a full reference dump.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if explainList {
			return runExplainList(cmd)
		}
		if explainAll {
			return runExplainAll(cmd)
		}

		if len(args) == 0 {
			return fmt.Errorf("please provide a finding ID (e.g., gogatoz explain VARIABLE_INJECTION)\n\nRun 'gogatoz explain --list' to see all available finding codes")
		}

		code := normalizeCode(args[0])
		info := analyze.LookupFinding(code)
		if info == nil {
			return fmt.Errorf("unknown finding code: %s\n\nRun 'gogatoz explain --list' to see all available finding codes", args[0])
		}

		if explainJSON {
			return printExplainJSON(cmd, info)
		}

		printFindingDetail(cmd, info)
		return nil
	},
}

func normalizeCode(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func runExplainList(cmd *cobra.Command) error {
	codes := analyze.AllFindings()
	if explainJSON {
		return printExplainJSON(cmd, codes)
	}
	for _, info := range codes {
		fmt.Fprintf(cmd.OutOrStdout(), "%-30s  [%s]  %s\n", info.ID, info.Severity, info.Title)
	}
	return nil
}

func runExplainAll(cmd *cobra.Command) error {
	codes := analyze.AllFindings()
	if explainJSON {
		return printExplainJSON(cmd, codes)
	}
	for i, info := range codes {
		if i > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("─", 60))
		}
		printFindingDetail(cmd, &info)
	}
	return nil
}

func printFindingDetail(cmd *cobra.Command, info *analyze.FindingCodeInfo) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "ID:          %s\n", info.ID)
	fmt.Fprintf(w, "Severity:    %s\n", info.Severity)
	fmt.Fprintf(w, "Title:       %s\n", info.Title)
	fmt.Fprintf(w, "\nDescription:\n  %s\n", info.Description)
	fmt.Fprintf(w, "\nRemediation:\n  %s\n", info.Remediation)
	if info.DocURL != "" {
		fmt.Fprintf(w, "\nDocumentation: %s\n", info.DocURL)
	}
	fmt.Fprintln(w)
}

func printExplainJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func init() {
	rootCmd.AddCommand(explainCmd)
	explainCmd.Flags().BoolVar(&explainJSON, "json", false, "Output as JSON")
	explainCmd.Flags().BoolVar(&explainList, "list", false, "List all available finding codes")
	explainCmd.Flags().BoolVar(&explainAll, "all", false, "Show details for all finding codes")
}
