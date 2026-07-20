package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/validate"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a GitLab token and probe its effective scopes",
	Long:  "Validates a GitLab token by probing API endpoints to map its effective capabilities: identity, scopes, admin status, and accessible resources.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if token == "" {
			return fmt.Errorf("GitLab token is required. Provide --token or set GITLAB_TOKEN")
		}
		ctx := context.Background()
		client, err := newGitLabClient()
		if err != nil {
			return err
		}
		profile, err := validate.ProbeToken(ctx, client)
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
		list := pterm.DefaultBulletList.WithItems(pairs)
		s, _ := list.Srender()
		fmt.Fprintln(w, s)

		// Capabilities table
		tableData := pterm.TableData{{"Capability", "Status", "Detail"}}
		for _, c := range profile.Capabilities {
			status := pterm.FgRed.Sprint("DENIED")
			if c.Accessible {
				status = pterm.FgGreen.Sprint("OK")
			}
			detail := c.Detail
			if detail == "" {
				detail = "-"
			}
			tableData = append(tableData, []string{c.Name, status, detail})
		}
		tbl, _ := pterm.DefaultTable.WithHasHeader().WithData(tableData).Srender()
		fmt.Fprintln(w, tbl)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
