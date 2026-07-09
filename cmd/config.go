package cmd

import (
	"fmt"
	"os"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage GoGatoZ configuration",
	Long:  "Inspect and generate .gogatoz.yaml configuration files.",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a .gogatoz.yaml with default controls",
	Long:  "Write a commented .gogatoz.yaml template to the current directory with all available controls options.",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := ".gogatoz.yaml"
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; remove it first or edit manually", path)
		}
		content := config.GenerateDefaultYAML()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display effective configuration",
	Long:  "Show the effective configuration after merging defaults, config file, environment, and flags.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Start with defaults and overlay any loaded controls
		effective := config.DefaultControls()
		if controlsCfg != nil {
			if len(controlsCfg.ForbiddenImageTags) > 0 {
				effective.ForbiddenImageTags = controlsCfg.ForbiddenImageTags
			}
			if len(controlsCfg.AuthorizedRegistries) > 0 {
				effective.AuthorizedRegistries = controlsCfg.AuthorizedRegistries
			}
			if len(controlsCfg.SecurityJobPatterns) > 0 {
				effective.SecurityJobPatterns = controlsCfg.SecurityJobPatterns
			}
			if len(controlsCfg.ControlledVariables) > 0 {
				effective.ControlledVariables = controlsCfg.ControlledVariables
			}
			if len(controlsCfg.DebugTraceVariables) > 0 {
				effective.DebugTraceVariables = controlsCfg.DebugTraceVariables
			}
			if len(controlsCfg.TrustedScriptURLs) > 0 {
				effective.TrustedScriptURLs = controlsCfg.TrustedScriptURLs
			}
			if len(controlsCfg.DisabledRules) > 0 {
				effective.DisabledRules = controlsCfg.DisabledRules
			}
		}

		w := cmd.OutOrStdout()
		if cfgUsed := viper.ConfigFileUsed(); cfgUsed != "" {
			fmt.Fprintf(w, "# config file: %s\n", cfgUsed)
		} else {
			fmt.Fprintln(w, "# no config file loaded (using defaults)")
		}

		out, err := yaml.Marshal(map[string]any{"controls": effective})
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		fmt.Fprint(w, string(out))
		return nil
	},
}

func init() {
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}
