package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/validate"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	validateProject string
	probeTokenFunc  = validate.ProbeTokenWithOptions
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a GitLab token and probe its effective scopes",
	Long:  "Validates a GitLab token with read-only API requests and maps confirmed, inferred, denied, and unknown capabilities. Optionally assess a specific project with --target.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("GitLab token is required. Provide --token or set GITLAB_TOKEN")
		}
		ctx := cmd.Context()
		client, err := newGitLabClient()
		if err != nil {
			return err
		}
		profile, err := probeTokenFunc(ctx, client, validate.ProbeOptions{
			Project: strings.TrimSpace(validateProject),
		})
		if err != nil {
			return err
		}

		w := cmd.OutOrStdout()
		if outputJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(profile)
		}

		// Identity section
		header := pterm.DefaultHeader.WithFullWidth()
		fmt.Fprintln(w, header.Sprint("Token Validation Results"))
		fmt.Fprintln(w)

		pairs := []pterm.BulletListItem{
			{Level: 0, Text: fmt.Sprintf("Username:   %s", profile.Username)},
			{Level: 0, Text: fmt.Sprintf("Name:       %s", profile.Name)},
			{Level: 0, Text: fmt.Sprintf("User ID:    %d", profile.UserID)},
			{Level: 0, Text: fmt.Sprintf("Admin:      %v", profile.IsAdmin)},
			{Level: 0, Text: fmt.Sprintf("Probe Mode: %s (no state-changing requests)", profile.ProbeMode)},
		}
		if profile.TokenName != "" {
			pairs = append(pairs, pterm.BulletListItem{Level: 0, Text: fmt.Sprintf("Token Name: %s", profile.TokenName)})
		}
		if len(profile.Scopes) > 0 {
			pairs = append(pairs, pterm.BulletListItem{Level: 0, Text: fmt.Sprintf("Scopes:     %s", strings.Join(profile.Scopes, ", "))})
		}
		if profile.ExpiresAt != "" {
			pairs = append(pairs, pterm.BulletListItem{Level: 0, Text: fmt.Sprintf("Expires:    %s", profile.ExpiresAt)})
		}
		if profile.Project != nil {
			pairs = append(pairs, pterm.BulletListItem{Level: 0, Text: fmt.Sprintf(
				"Target:     %s — %s (%d)", profile.Project.Path,
				profile.Project.AccessLevelName, profile.Project.AccessLevel,
			)})
		}
		list := pterm.DefaultBulletList.WithItems(pairs)
		s, _ := list.Srender()
		fmt.Fprintln(w, s)

		// Capabilities table
		tableData := pterm.TableData{{"Capability", "Status", "Confidence", "Detail"}}
		for _, c := range profile.Capabilities {
			status := renderCapabilityStatus(c.Status)
			detail := c.Detail
			if detail == "" {
				detail = strings.Join(c.Evidence, "; ")
			}
			if detail == "" {
				detail = "-"
			}
			tableData = append(tableData, []string{c.Name, status, c.Confidence, detail})
		}
		tbl, _ := pterm.DefaultTable.WithHasHeader().WithData(tableData).Srender()
		fmt.Fprintln(w, tbl)

		return nil
	},
}

func renderCapabilityStatus(status validate.CapabilityStatus) string {
	switch status {
	case validate.StatusConfirmed:
		return pterm.FgGreen.Sprint("CONFIRMED")
	case validate.StatusInferred:
		return pterm.FgYellow.Sprint("INFERRED")
	case validate.StatusDenied:
		return pterm.FgRed.Sprint("DENIED")
	default:
		return pterm.FgGray.Sprint("UNKNOWN")
	}
}

func init() {
	validateCmd.Flags().StringVarP(&validateProject, "target", "t", "", "Optional project ID or path for read-only project-specific capability inference")
	rootCmd.AddCommand(validateCmd)
}
