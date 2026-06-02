package notify

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

const maxEmbedsPerMessage = 10

// severityColor returns the Discord embed color for a severity level.
func severityColor(s analyze.Severity) int {
	switch s {
	case analyze.SeverityCritical:
		return ColorCritical
	case analyze.SeverityHigh:
		return ColorHigh
	case analyze.SeverityMedium:
		return ColorMedium
	case analyze.SeverityLow:
		return ColorLow
	case analyze.SeverityInformational:
		return ColorInformational
	default:
		return ColorInfo
	}
}

// severityEmoji returns a Discord-safe emoji for a severity level.
func severityEmoji(s analyze.Severity) string {
	switch s {
	case analyze.SeverityCritical:
		return "\U0001F7E3" // purple circle
	case analyze.SeverityHigh:
		return "\U0001F534" // red circle
	case analyze.SeverityMedium:
		return "\U0001F7E0" // orange circle
	case analyze.SeverityLow:
		return "\U0001F7E1" // yellow circle
	case analyze.SeverityInformational:
		return "\u26AA" // white circle
	default:
		return "\U0001F535" // blue circle
	}
}

// countFindings returns a map of severity → count across all results.
func countFindings(results []enumerate.Result) map[analyze.Severity]int {
	counts := map[analyze.Severity]int{}
	for _, r := range results {
		for _, f := range r.Findings {
			counts[f.Severity]++
		}
	}
	return counts
}

// totalFindings returns the total number of findings across all results.
func totalFindings(results []enumerate.Result) int {
	n := 0
	for _, r := range results {
		n += len(r.Findings)
	}
	return n
}

// FormatDiscordMessages converts enumerate results into Discord-ready Messages
// with embeds, chunked to respect Discord's 10-embeds-per-message limit.
func FormatDiscordMessages(results []enumerate.Result) []Message {
	counts := countFindings(results)
	total := totalFindings(results)

	// Build summary embed
	var summaryFields []DiscordEmbedField
	for _, sev := range analyze.AllSeverities {
		if c := counts[sev]; c > 0 {
			summaryFields = append(summaryFields, DiscordEmbedField{
				Name:   fmt.Sprintf("%s %s", severityEmoji(sev), string(sev)),
				Value:  fmt.Sprintf("%d", c),
				Inline: true,
			})
		}
	}

	var summaryColor int
	switch {
	case counts[analyze.SeverityCritical] > 0:
		summaryColor = ColorCritical
	case counts[analyze.SeverityHigh] > 0:
		summaryColor = ColorHigh
	case counts[analyze.SeverityMedium] > 0:
		summaryColor = ColorMedium
	case counts[analyze.SeverityLow] > 0:
		summaryColor = ColorLow
	default:
		summaryColor = ColorInfo
	}

	summary := DiscordEmbed{
		Title:       "GoGatoZ Scan Results",
		Description: fmt.Sprintf("**%d** projects scanned | **%d** findings", len(results), total),
		Color:       summaryColor,
		Fields:      summaryFields,
		Footer:      &DiscordEmbedFooter{Text: "GoGatoZ"},
	}

	// Build per-finding embeds
	var embeds []DiscordEmbed
	embeds = append(embeds, summary)

	for _, r := range results {
		for _, f := range r.Findings {
			desc := f.Title
			if f.Evidence != "" {
				desc += "\n```\n" + truncate(f.Evidence, 512) + "\n```"
			}

			var fields []DiscordEmbedField
			fields = append(fields, DiscordEmbedField{
				Name:   "Project",
				Value:  r.ProjectPathWithNS,
				Inline: true,
			})
			if f.JobName != "" {
				fields = append(fields, DiscordEmbedField{
					Name:   "Job",
					Value:  fmt.Sprintf("`%s`", f.JobName),
					Inline: true,
				})
			}
			if f.Recommendation != "" {
				fields = append(fields, DiscordEmbedField{
					Name:  "Recommendation",
					Value: truncate(f.Recommendation, 256),
				})
			}

			embeds = append(embeds, DiscordEmbed{
				Title:       fmt.Sprintf("%s %s", severityEmoji(f.Severity), f.ID),
				Description: truncate(desc, 4000),
				Color:       severityColor(f.Severity),
				Fields:      fields,
			})
		}
	}

	// Chunk embeds into messages of max 10
	var msgs []Message
	var msgType string
	switch {
	case counts[analyze.SeverityCritical] > 0 || counts[analyze.SeverityHigh] > 0:
		msgType = TypeFailure
	case counts[analyze.SeverityMedium] > 0:
		msgType = TypeWarning
	case total == 0:
		msgType = TypeSuccess
	default:
		msgType = TypeInfo
	}

	for i := 0; i < len(embeds); i += maxEmbedsPerMessage {
		end := min(i+maxEmbedsPerMessage, len(embeds))
		msgs = append(msgs, Message{
			Title:  "GoGatoZ Scan Results",
			Embeds: embeds[i:end],
			Type:   msgType,
		})
	}

	if len(msgs) == 0 {
		msgs = append(msgs, Message{
			Title:  "GoGatoZ Scan Results",
			Embeds: []DiscordEmbed{summary},
			Type:   TypeSuccess,
		})
	}

	return msgs
}

// FormatAppriseMarkdown converts enumerate results into a single Apprise-ready
// Message with a markdown body.
func FormatAppriseMarkdown(results []enumerate.Result) Message {
	counts := countFindings(results)
	total := totalFindings(results)

	var b strings.Builder
	b.WriteString("## GoGatoZ Scan Results\n\n")
	fmt.Fprintf(&b, "**%d** projects scanned | **%d** findings\n\n", len(results), total)

	if total == 0 {
		b.WriteString("No findings detected.\n")
		return Message{
			Title: "GoGatoZ Scan Results",
			Body:  b.String(),
			Type:  TypeSuccess,
		}
	}

	// Group findings by severity
	type projectFinding struct {
		project string
		finding analyze.Finding
	}
	bySeverity := map[analyze.Severity][]projectFinding{}
	for _, r := range results {
		for _, f := range r.Findings {
			bySeverity[f.Severity] = append(bySeverity[f.Severity], projectFinding{
				project: r.ProjectPathWithNS,
				finding: f,
			})
		}
	}

	for _, sev := range analyze.AllSeverities {
		pfs := bySeverity[sev]
		if len(pfs) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s %s (%d)\n\n", severityEmoji(sev), string(sev), counts[sev])
		for _, pf := range pfs {
			line := fmt.Sprintf("- **%s** in `%s`", pf.finding.ID, pf.project)
			if pf.finding.Title != "" {
				line += " — " + pf.finding.Title
			}
			if pf.finding.Evidence != "" {
				line += fmt.Sprintf(" (`%s`)", truncate(pf.finding.Evidence, 120))
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	var msgType string
	switch {
	case counts[analyze.SeverityCritical] > 0 || counts[analyze.SeverityHigh] > 0:
		msgType = TypeFailure
	case counts[analyze.SeverityMedium] > 0:
		msgType = TypeWarning
	default:
		msgType = TypeInfo
	}

	return Message{
		Title: "GoGatoZ Scan Results",
		Body:  b.String(),
		Type:  msgType,
	}
}

// truncate limits s to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
