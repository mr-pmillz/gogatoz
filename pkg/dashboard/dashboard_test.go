package dashboard

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestBuild(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "group/clean",
			HasCIPipeline:     true,
			ProtectedBranches: []string{"main"},
		},
		{
			ProjectPathWithNS: "group/vuln",
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "TEST", Severity: analyze.SeverityCritical},
				{ID: "TEST2", Severity: analyze.SeverityHigh},
			},
		},
		{
			ProjectPathWithNS: "group/noci",
			HasCIPipeline:     false,
		},
	}

	d := Build(results, "test-group", 1)

	if d.GroupName != "test-group" {
		t.Errorf("GroupName = %s, want test-group", d.GroupName)
	}
	if d.ProjectCount != 3 {
		t.Errorf("ProjectCount = %d, want 3", d.ProjectCount)
	}
	if d.ScannedCount != 3 {
		t.Errorf("ScannedCount = %d, want 3", d.ScannedCount)
	}
	if len(d.Scorecards) != 3 {
		t.Errorf("Scorecards len = %d, want 3", len(d.Scorecards))
	}
	if d.Aggregate.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", d.Aggregate.TotalFindings)
	}
	if d.Aggregate.TotalCritical != 1 {
		t.Errorf("TotalCritical = %d, want 1", d.Aggregate.TotalCritical)
	}
	if len(d.TopFindings) == 0 {
		t.Error("expected at least 1 top finding")
	}
}

func TestBuild_Empty(t *testing.T) {
	d := Build(nil, "empty", 0)
	if d.ProjectCount != 0 {
		t.Errorf("expected 0 projects, got %d", d.ProjectCount)
	}
	if len(d.Scorecards) != 0 {
		t.Errorf("expected 0 scorecards, got %d", len(d.Scorecards))
	}
}

func TestBuild_RiskDistribution(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "group/clean1",
			HasCIPipeline:     true,
			ProtectedBranches: []string{"main"},
		},
		{
			ProjectPathWithNS: "group/clean2",
			HasCIPipeline:     true,
			ProtectedBranches: []string{"main"},
		},
		{
			ProjectPathWithNS: "group/crit",
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "C1", Severity: analyze.SeverityCritical},
				{ID: "C2", Severity: analyze.SeverityCritical},
				{ID: "C3", Severity: analyze.SeverityCritical},
				{ID: "C4", Severity: analyze.SeverityCritical},
				{ID: "C5", Severity: analyze.SeverityCritical},
				{ID: "C6", Severity: analyze.SeverityCritical},
				{ID: "C7", Severity: analyze.SeverityCritical},
			},
		},
	}

	d := Build(results, "mixed", 2)

	if d.RiskDistribution.Clean != 2 {
		t.Errorf("Clean = %d, want 2", d.RiskDistribution.Clean)
	}
	if d.RiskDistribution.Critical != 1 {
		t.Errorf("Critical = %d, want 1", d.RiskDistribution.Critical)
	}
}

func TestBuild_SortsScorecardsByScoreAscending(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "group/clean",
			HasCIPipeline:     true,
			ProtectedBranches: []string{"main"},
		},
		{
			ProjectPathWithNS: "group/vuln",
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "C1", Severity: analyze.SeverityCritical},
				{ID: "C2", Severity: analyze.SeverityCritical},
			},
		},
	}

	d := Build(results, "sorted", 3)

	if len(d.Scorecards) < 2 {
		t.Fatal("expected at least 2 scorecards")
	}
	if d.Scorecards[0].Score > d.Scorecards[1].Score {
		t.Errorf("scorecards not sorted ascending: %d > %d",
			d.Scorecards[0].Score, d.Scorecards[1].Score)
	}
}

func TestBuild_FPFindingsExcluded(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "group/fp",
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "FP1", Severity: analyze.SeverityCritical, FalsePositive: true},
				{ID: "REAL", Severity: analyze.SeverityHigh},
			},
		},
	}

	d := Build(results, "fp-test", 4)

	if d.Aggregate.TotalFindings != 1 {
		t.Errorf("TotalFindings = %d, want 1 (FP should be excluded)", d.Aggregate.TotalFindings)
	}
	if d.Aggregate.TotalCritical != 0 {
		t.Errorf("TotalCritical = %d, want 0 (FP critical excluded)", d.Aggregate.TotalCritical)
	}
	if d.Aggregate.TotalHigh != 1 {
		t.Errorf("TotalHigh = %d, want 1", d.Aggregate.TotalHigh)
	}
}
