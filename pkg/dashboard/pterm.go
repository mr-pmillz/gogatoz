package dashboard

import (
	"fmt"
	"io"

	"github.com/pterm/pterm"
)

// RenderPTerm writes a human-readable dashboard to w using pterm tables and styled text.
func RenderPTerm(w io.Writer, d Dashboard) {
	header := pterm.DefaultHeader.WithFullWidth()
	fmt.Fprintln(w, header.Sprint(fmt.Sprintf("Security Dashboard: %s", d.GroupName)))

	fmt.Fprintf(w, "Projects: %d | Mean Score: %d | Median Score: %d\n",
		d.ProjectCount, d.Aggregate.MeanScore, d.Aggregate.MedianScore)
	fmt.Fprintf(w, "CI Coverage: %.0f%% | Security Jobs: %.0f%% | Protected Branches: %.0f%%\n\n",
		d.Aggregate.CICoverage, d.Aggregate.SecurityJobCoverage, d.Aggregate.ProtectedBranchCoverage)

	fmt.Fprintf(w, "Risk Distribution: Critical=%d High=%d Medium=%d Low=%d Clean=%d\n\n",
		d.RiskDistribution.Critical, d.RiskDistribution.High,
		d.RiskDistribution.Medium, d.RiskDistribution.Low, d.RiskDistribution.Clean)

	tableData := pterm.TableData{{"Project", "Score", "Tier", "CRIT", "HIGH", "MED", "LOW", "CI", "SecJobs", "Protected"}}
	for _, sc := range d.Scorecards {
		ci, sec, prot := "no", "no", "no"
		if sc.HasCI {
			ci = "yes"
		}
		if sc.HasSecurityJobs {
			sec = "yes"
		}
		if sc.HasProtectedBranches {
			prot = "yes"
		}
		tableData = append(tableData, []string{
			sc.ProjectPath,
			fmt.Sprintf("%d", sc.Score),
			sc.RiskTier,
			fmt.Sprintf("%d", sc.FindingsBySeverity["CRITICAL"]),
			fmt.Sprintf("%d", sc.FindingsBySeverity["HIGH"]),
			fmt.Sprintf("%d", sc.FindingsBySeverity["MEDIUM"]),
			fmt.Sprintf("%d", sc.FindingsBySeverity["LOW"]),
			ci, sec, prot,
		})
	}
	s, _ := pterm.DefaultTable.WithHasHeader().WithData(tableData).Srender()
	fmt.Fprintln(w, s)

	if len(d.TopFindings) > 0 {
		fmt.Fprintln(w, "\nTop Findings:")
		for _, f := range d.TopFindings {
			fmt.Fprintf(w, "  [%s] %s — %d occurrences across %d projects\n",
				f.Severity, f.FindingID, f.Count, f.ProjectCount)
		}
	}
}
