package dashboard

import (
	"sort"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

// Dashboard is the aggregate security posture view for a GitLab group.
type Dashboard struct {
	GroupName        string             `json:"group_name"`
	GroupID          int64              `json:"group_id"`
	GeneratedAt      time.Time          `json:"generated_at"`
	ProjectCount     int                `json:"project_count"`
	ScannedCount     int                `json:"scanned_count"`
	Scorecards       []ProjectScorecard `json:"scorecards"`
	Aggregate        AggregateMetrics   `json:"aggregate"`
	TopFindings      []FindingFrequency `json:"top_findings"`
	RiskDistribution RiskDistribution   `json:"risk_distribution"`
}

// AggregateMetrics captures group-wide summary statistics.
type AggregateMetrics struct {
	MeanScore               int     `json:"mean_score"`
	MedianScore             int     `json:"median_score"`
	CICoverage              float64 `json:"ci_coverage"`
	SecurityJobCoverage     float64 `json:"security_job_coverage"`
	ProtectedBranchCoverage float64 `json:"protected_branch_coverage"`
	TotalFindings           int     `json:"total_findings"`
	TotalCritical           int     `json:"total_critical"`
	TotalHigh               int     `json:"total_high"`
}

// FindingFrequency records how often a particular finding ID appears across projects.
type FindingFrequency struct {
	FindingID    string `json:"finding_id"`
	Count        int    `json:"count"`
	ProjectCount int    `json:"project_count"`
	Severity     string `json:"severity"`
}

// RiskDistribution counts projects in each risk tier.
type RiskDistribution struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Clean    int `json:"clean"`
}

// Build creates a Dashboard from enumeration results.
func Build(results []enumerate.Result, groupName string, groupID int64) Dashboard {
	d := Dashboard{
		GroupName:    groupName,
		GroupID:      groupID,
		GeneratedAt:  time.Now(),
		ProjectCount: len(results),
		ScannedCount: len(results),
	}

	if len(results) == 0 {
		return d
	}

	scores := make([]int, 0, len(results))
	findingCounts := map[string]int{}
	findingProjects := map[string]map[string]bool{}
	findingSeverity := map[string]string{}
	ciCount, secJobCount, protCount := 0, 0, 0

	for _, r := range results {
		sc := ScoreProject(r)
		d.Scorecards = append(d.Scorecards, sc)
		scores = append(scores, sc.Score)

		switch sc.RiskTier {
		case "Critical":
			d.RiskDistribution.Critical++
		case "High":
			d.RiskDistribution.High++
		case "Medium":
			d.RiskDistribution.Medium++
		case "Low":
			d.RiskDistribution.Low++
		case "Clean":
			d.RiskDistribution.Clean++
		}

		if sc.HasCI {
			ciCount++
		}
		if sc.HasSecurityJobs {
			secJobCount++
		}
		if sc.HasProtectedBranches {
			protCount++
		}

		for _, f := range r.Findings {
			if f.FalsePositive {
				continue
			}
			d.Aggregate.TotalFindings++
			switch f.Severity {
			case analyze.SeverityCritical:
				d.Aggregate.TotalCritical++
			case analyze.SeverityHigh:
				d.Aggregate.TotalHigh++
			}

			findingCounts[f.ID]++
			if findingProjects[f.ID] == nil {
				findingProjects[f.ID] = map[string]bool{}
			}
			findingProjects[f.ID][r.ProjectPathWithNS] = true
			findingSeverity[f.ID] = string(f.Severity)
		}
	}

	sort.Ints(scores)
	total := 0
	for _, s := range scores {
		total += s
	}
	d.Aggregate.MeanScore = total / len(scores)
	d.Aggregate.MedianScore = scores[len(scores)/2]

	n := float64(len(results))
	d.Aggregate.CICoverage = float64(ciCount) / n * 100
	d.Aggregate.SecurityJobCoverage = float64(secJobCount) / n * 100
	d.Aggregate.ProtectedBranchCoverage = float64(protCount) / n * 100

	for id, count := range findingCounts {
		d.TopFindings = append(d.TopFindings, FindingFrequency{
			FindingID:    id,
			Count:        count,
			ProjectCount: len(findingProjects[id]),
			Severity:     findingSeverity[id],
		})
	}
	sort.Slice(d.TopFindings, func(i, j int) bool {
		return d.TopFindings[i].Count > d.TopFindings[j].Count
	})
	if len(d.TopFindings) > 20 {
		d.TopFindings = d.TopFindings[:20]
	}

	// Sort scorecards by score ascending (worst first).
	sort.Slice(d.Scorecards, func(i, j int) bool {
		return d.Scorecards[i].Score < d.Scorecards[j].Score
	})

	return d
}
