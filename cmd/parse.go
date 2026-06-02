package cmd

import "github.com/spf13/cobra"

// parseCmd is the parent command for parse subcommands.
// It overrides PersistentPreRunE so that subcommands do not require
// a GitLab token or config initialization.
var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Parse and transform GoGatoZ output",
	Long:  "Parse subcommands operate on GoGatoZ JSONL output locally — no GitLab token required.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil // no config/token needed
	},
}

func init() {
	rootCmd.AddCommand(parseCmd)
}
