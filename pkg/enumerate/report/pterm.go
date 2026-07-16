package report

import (
	"fmt"
	"io"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/pterm/pterm"
)

// severityColor returns a pterm style for the given severity level.
func severityColor(s analyze.Severity) *pterm.Style {
	switch s {
	case analyze.SeverityCritical:
		return pterm.NewStyle(pterm.FgLightMagenta, pterm.Bold)
	case analyze.SeverityHigh:
		return pterm.NewStyle(pterm.FgRed, pterm.Bold)
	case analyze.SeverityMedium:
		return pterm.NewStyle(pterm.FgYellow, pterm.Bold)
	case analyze.SeverityLow:
		return pterm.NewStyle(pterm.FgGreen)
	case analyze.SeverityInformational:
		return pterm.NewStyle(pterm.FgCyan)
	default:
		return pterm.NewStyle(pterm.FgWhite)
	}
}

// colorSev returns the severity string colored according to its level.
func colorSev(s analyze.Severity) string {
	return severityColor(s).Sprint(string(s))
}

// colorCount returns a colored number: nonzero uses severity color, zero is dimmed.
func colorCount(n int, s analyze.Severity) string {
	if n == 0 {
		return pterm.FgDarkGray.Sprint("0")
	}
	return severityColor(s).Sprint(n)
}

// truncate returns s trimmed to max chars with "..." if needed.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// RenderPTerm writes a human-readable report using pterm tables and styled text.
func RenderPTerm(w io.Writer, r Report) error {
	if len(r.Projects) == 0 {
		s := pterm.Info.Sprint("No projects to report")
		fmt.Fprintln(w, s)
		return nil
	}

	// Summary header
	summaryHeader := fmt.Sprintf("Enumeration Results — %d projects scanned", r.Summary.Total)
	s := pterm.DefaultHeader.Sprint(summaryHeader)
	fmt.Fprintln(w, s)

	// Summary stats line
	stats := fmt.Sprintf("Findings: %s total  |  %s CRIT  %s HIGH  %s MED  %s LOW  %s INFO  |  Exploitable: %d",
		pterm.Bold.Sprint(r.Summary.Findings),
		colorCount(r.Summary.BySeverityStr["CRITICAL"], analyze.SeverityCritical),
		colorCount(r.Summary.BySeverityStr["HIGH"], analyze.SeverityHigh),
		colorCount(r.Summary.BySeverityStr["MEDIUM"], analyze.SeverityMedium),
		colorCount(r.Summary.BySeverityStr["LOW"], analyze.SeverityLow),
		colorCount(r.Summary.BySeverityStr["INFORMATIONAL"], analyze.SeverityInformational),
		r.Summary.Exploitable,
	)
	fmt.Fprintln(w, stats)

	// Score banner (if computed)
	if r.Score != nil {
		scoreStyle := pterm.NewStyle(pterm.FgGreen, pterm.Bold)
		switch r.Score.Score {
		case "C":
			scoreStyle = pterm.NewStyle(pterm.FgYellow, pterm.Bold)
		case "D", "E":
			scoreStyle = pterm.NewStyle(pterm.FgRed, pterm.Bold)
		}
		scoreLine := fmt.Sprintf("Security Score: %s  (%.0f/100 pts)",
			scoreStyle.Sprint(r.Score.Score), r.Score.FinalPoints)
		if r.Score.CriticalMalusApplied {
			scoreLine += pterm.FgRed.Sprint("  [critical finding — capped at E]")
		}
		fmt.Fprintln(w, scoreLine)
	}
	fmt.Fprintln(w)

	// Projects table
	if err := renderProjectsTable(w, r.Projects); err != nil {
		return err
	}

	// Per-project findings detail
	if err := renderProjectFindings(w, r.Projects); err != nil {
		return err
	}

	// False positive summary (when filtering is active)
	if r.Summary.FP.Enabled {
		if err := renderFPSummary(w, r.Summary.FP); err != nil {
			return err
		}
	}

	// Supply chain risk summary
	if r.SupplyChain.TotalRisk > 0 {
		renderSupplyChainSection(w, r.SupplyChain)
	}

	// Runner, pipeline, and log stats
	return renderStatsSection(w, r)
}

// renderProjectsTable renders the projects overview table.
func renderProjectsTable(w io.Writer, projects []ProjectView) error {
	tableData := pterm.TableData{
		{"Project", "Stars", "Findings", "CRIT", "HIGH", "MED", "LOW", "INFO", "CI Summary"},
	}
	for _, pv := range projects {
		tableData = append(tableData, []string{
			pv.Project.ProjectPathWithNS,
			fmt.Sprint(pv.Project.StarCount),
			fmt.Sprint(pv.FindingCount),
			colorCount(pv.Critical, analyze.SeverityCritical),
			colorCount(pv.High, analyze.SeverityHigh),
			colorCount(pv.Medium, analyze.SeverityMedium),
			colorCount(pv.Low, analyze.SeverityLow),
			colorCount(pv.Informational, analyze.SeverityInformational),
			truncate(pv.Project.CISummary, 60),
		})
	}

	tbl, err := pterm.DefaultTable.
		WithHasHeader().
		WithData(tableData).
		WithLeftAlignment().
		Srender()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, tbl)
	return nil
}

// renderProjectFindings renders per-project findings detail sections.
func renderProjectFindings(w io.Writer, projects []ProjectView) error {
	for _, pv := range projects {
		if pv.FindingCount == 0 {
			continue
		}

		projHeader := fmt.Sprintf("%s  (%d findings)", pv.Project.ProjectPathWithNS, pv.FindingCount)
		secStr := pterm.DefaultSection.Sprint(projHeader)
		fmt.Fprint(w, secStr)

		var items []pterm.BulletListItem
		for _, f := range pv.Project.Findings {
			label := fmt.Sprintf("%s %s: %s", colorSev(f.Severity), f.ID, f.Title)
			items = append(items, pterm.BulletListItem{Level: 0, Text: label})

			if f.JobName != "" {
				items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("job: %s", f.JobName)})
			}
			if f.Evidence != "" {
				items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("evidence: %s", truncate(f.Evidence, 160))})
			}
			if f.Recommendation != "" {
				items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("recommendation: %s", truncate(f.Recommendation, 160))})
			}
		}

		bl, err := pterm.DefaultBulletList.WithItems(items).Srender()
		if err != nil {
			return err
		}
		fmt.Fprintln(w, bl)
	}
	return nil
}

// renderStatsSection renders runner, pipeline, and log statistics.
func renderStatsSection(w io.Writer, r Report) error {
	var statsItems []pterm.BulletListItem

	statsItems = appendRunnerStats(statsItems, r.Runners)
	statsItems = appendPipelineStats(statsItems, r.Pipelines)

	if r.LogFindingsTotal > 0 {
		statsItems = append(statsItems, pterm.BulletListItem{Level: 0, Text: pterm.Bold.Sprint("Logs")})
		statsItems = append(statsItems, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Findings in logs: %d", r.LogFindingsTotal)})
	}

	if len(statsItems) == 0 {
		return nil
	}

	bl, err := pterm.DefaultBulletList.WithItems(statsItems).Srender()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, bl)
	return nil
}

// renderFPSummary renders the false positive filtering summary section.
func renderFPSummary(w io.Writer, fp FPSummary) error {
	secStr := pterm.DefaultSection.Sprint("False Positive Summary")
	fmt.Fprint(w, secStr)

	items := []pterm.BulletListItem{
		{Level: 0, Text: fmt.Sprintf("Raw findings: %s", pterm.Bold.Sprint(fp.RawFindings))},
		{Level: 0, Text: fmt.Sprintf("False positives filtered: %s", pterm.FgYellow.Sprint(fp.FalsePositives))},
		{Level: 0, Text: fmt.Sprintf("Adjusted findings: %s", pterm.Bold.Sprint(fp.AdjustedFindings))},
	}

	if len(fp.ByReason) > 0 {
		items = append(items, pterm.BulletListItem{Level: 0, Text: pterm.Bold.Sprint("By reason:")})
		for reason, count := range fp.ByReason {
			items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("%s: %d", reason, count)})
		}
	}

	bl, err := pterm.DefaultBulletList.WithItems(items).Srender()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, bl)
	return nil
}

// appendRunnerStats adds runner statistics bullet items.
func appendRunnerStats(items []pterm.BulletListItem, rv RunnersView) []pterm.BulletListItem {
	if rv.ProjectsWithTagged == 0 && rv.MRTagged == 0 && rv.ExposedBroad == 0 {
		return items
	}
	items = append(items, pterm.BulletListItem{Level: 0, Text: pterm.Bold.Sprint("Runners")})
	items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Tagged projects: %d", rv.ProjectsWithTagged)})
	items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("MR-triggered on tagged: %d", rv.MRTagged)})
	items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Exposed broad: %d", rv.ExposedBroad)})
	if rv.RiskyShellExecutors > 0 {
		items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Risky shell executors: %d", rv.RiskyShellExecutors)})
	}
	if rv.RiskyDockerExecutors > 0 {
		items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Risky docker executors: %d", rv.RiskyDockerExecutors)})
	}
	return items
}

// appendPipelineStats adds pipeline statistics bullet items.
func appendPipelineStats(items []pterm.BulletListItem, pv PipelinesView) []pterm.BulletListItem {
	items = append(items, pterm.BulletListItem{Level: 0, Text: pterm.Bold.Sprint("Pipelines")})
	items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("With CI: %d", pv.ProjectsWithCI)})
	if pv.RemoteIncludes > 0 {
		items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Remote includes: %d", pv.RemoteIncludes)})
	}
	if pv.UnpinnedProjectIncludes > 0 {
		items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Unpinned includes: %d", pv.UnpinnedProjectIncludes)})
	}
	if pv.Components > 0 {
		items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Components: %d", pv.Components)})
	}
	return items
}

func renderSupplyChainSection(w io.Writer, sc SupplyChainView) {
	var items []pterm.BulletListItem
	items = append(items, pterm.BulletListItem{Level: 0, Text: pterm.Bold.Sprint("Supply Chain Risk Summary")})
	add := func(label string, count int) {
		if count > 0 {
			items = append(items, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("%s: %d", label, count)})
		}
	}
	add("Exfiltration findings", sc.ExfilFindings)
	add("Encoded payloads", sc.EncodedPayloads)
	add("Campaign matches", sc.CampaignMatches)
	add("Suspicious network targets", sc.SuspiciousNetwork)
	add("Obfuscation issues", sc.ObfuscationIssues)
	add("Weak branch protection", sc.WeakProtection)
	add("Dependency confusion", sc.DepConfusion)
	add("AI config risk", sc.AIConfigRisk)
	add("OIDC provenance anomaly", sc.OIDCAnomaly)
	items = append(items, pterm.BulletListItem{Level: 1, Text: pterm.Bold.Sprintf("Total risk indicators: %d", sc.TotalRisk)})

	if bl, err := pterm.DefaultBulletList.WithItems(items).Srender(); err == nil {
		fmt.Fprintln(w, bl)
	}
}
