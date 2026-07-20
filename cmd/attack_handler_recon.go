package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	rorpkg "github.com/mr-pmillz/gogatoz/pkg/attack/ror"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// runAttackPayloadOnly prints YAML/JSON payload and exits; no token/target required.
func runAttackPayloadOnly(cmd *cobra.Command) error {
	if strings.TrimSpace(atkPayload) == "" {
		return fmt.Errorf("--payload is required when --payload-only is set")
	}
	// LOTP payloads use a different output format (JSON with file paths)
	lp := strings.ToLower(strings.TrimSpace(atkPayload))
	if strings.HasPrefix(lp, "lotp-") || lp == "gyp" {
		lotpTool := strings.TrimPrefix(lp, "lotp-")
		if lotpTool == lp { // no lotp- prefix; must be "gyp"
			lotpTool = lp
		}
		if strings.TrimSpace(atkCmd) == "" {
			return fmt.Errorf("--cmd is required for LOTP payloads")
		}
		p, perr := payloadgen.GenerateLOTPPayload(lotpTool, atkCmd)
		if perr != nil {
			return fmt.Errorf("generate LOTP payload: %w", perr)
		}
		type fileOut struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		out := struct {
			Tool        string    `json:"tool"`
			Files       []fileOut `json:"files"`
			Description string    `json:"description"`
			Reference   string    `json:"reference"`
		}{
			Tool:        p.Tool,
			Description: p.Description,
			Reference:   p.Reference,
		}
		for _, f := range p.Files {
			out.Files = append(out.Files, fileOut{Path: f.Path, Content: f.Content})
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	yaml, err := renderPayload()
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(cmd.OutOrStdout(), yaml)
	return err
}

// runAttackDiscoverTags lists runner tags for the target project and exits.
func runAttackDiscoverTags(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	tags, _, err := rorpkg.DiscoverProjectRunnerTags(ctx, client, atkTarget)
	if err != nil {
		return err
	}
	if strings.TrimSpace(atkExecutor) != "" {
		tags = rorpkg.FilterTagsByExecutor(tags, atkExecutor)
	}
	if outputJSON {
		// print as simple JSON array
		q := make([]string, 0, len(tags))
		for _, t := range tags {
			q = append(q, fmt.Sprintf("%q", t))
		}
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "[%s]\n", strings.Join(q, ", "))
		if err != nil {
			return err
		}
		return nil
	}
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Runner tags: %s", strings.Join(tags, ", ")))
	return nil
}
