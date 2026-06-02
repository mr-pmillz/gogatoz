package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestBuild_Aggregates_LogFindings_Total(t *testing.T) {
	in := []enumerate.Result{
		{ProjectID: 1, ProjectPathWithNS: "g/a", HasCIPipeline: true, CISummary: "jobs=1", LogFindingsCount: 2, Findings: []analyze.Finding{{ID: "X", Severity: analyze.SeverityLow}}},
		{ProjectID: 2, ProjectPathWithNS: "g/b", HasCIPipeline: true, CISummary: "jobs=0", LogFindingsCount: 0},
		{ProjectID: 3, ProjectPathWithNS: "g/c", HasCIPipeline: true, CISummary: "jobs=3", LogFindingsCount: 5, Findings: []analyze.Finding{{ID: "Y", Severity: analyze.SeverityHigh}}},
	}
	rep := Build(in, Options{})
	if rep.LogFindingsTotal != 7 {
		t.Fatalf("expected total log findings=7, got %d", rep.LogFindingsTotal)
	}
	// Quick sanity on severity aggregation
	if rep.Summary.BySeverity[analyze.SeverityHigh] != 1 {
		t.Fatalf("expected 1 HIGH finding, got %d", rep.Summary.BySeverity[analyze.SeverityHigh])
	}
}

func TestBuild_ExploitableCount(t *testing.T) {
	in := []enumerate.Result{
		{
			ProjectID: 1, ProjectPathWithNS: "g/a", HasCIPipeline: true, CISummary: "jobs=1",
			Findings: []analyze.Finding{
				{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityHigh},
				{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium},
			},
		},
		{
			ProjectID: 2, ProjectPathWithNS: "g/b", HasCIPipeline: true, CISummary: "jobs=1",
			Findings: []analyze.Finding{
				{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh}, // not exploitable
			},
		},
		{
			ProjectID: 3, ProjectPathWithNS: "g/c", HasCIPipeline: true, CISummary: "jobs=0",
		},
	}
	rep := Build(in, Options{})
	// Only g/a has exploitable findings (SELF_HOSTED_EXPOSED, PLAINTEXT_SECRET)
	// g/b has INCLUDE_REMOTE which is informational
	if rep.Summary.Exploitable != 1 {
		t.Fatalf("expected Exploitable=1, got %d", rep.Summary.Exploitable)
	}
}

func TestBuild_FPSummary(t *testing.T) {
	in := []enumerate.Result{
		{
			ProjectID: 1, ProjectPathWithNS: "g/a", HasCIPipeline: true,
			Findings: []analyze.Finding{
				{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, FalsePositive: true, FalsePositiveReason: "FP_GITLAB_CI_FLAG"},
				{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh},
			},
		},
		{
			ProjectID: 2, ProjectPathWithNS: "g/b", HasCIPipeline: true,
			Findings: []analyze.Finding{
				{ID: "ARTIFACTS_NO_EXPIRE", Severity: analyze.SeverityLow, FalsePositive: true, FalsePositiveReason: "FP_PAGES_ARTIFACTS"},
				{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityHigh},
			},
		},
	}

	t.Run("without_filter", func(t *testing.T) {
		rep := Build(in, Options{})
		if rep.Summary.FP.Enabled {
			t.Error("FP.Enabled should be false when not filtering")
		}
		// All 4 findings should be counted
		if rep.Summary.Findings != 4 {
			t.Errorf("expected 4 findings, got %d", rep.Summary.Findings)
		}
	})

	t.Run("with_filter", func(t *testing.T) {
		rep := Build(in, Options{FilterFalsePositives: true})
		if !rep.Summary.FP.Enabled {
			t.Fatal("FP.Enabled should be true")
		}
		if rep.Summary.FP.RawFindings != 4 {
			t.Errorf("RawFindings = %d, want 4", rep.Summary.FP.RawFindings)
		}
		if rep.Summary.FP.FalsePositives != 2 {
			t.Errorf("FalsePositives = %d, want 2", rep.Summary.FP.FalsePositives)
		}
		if rep.Summary.FP.AdjustedFindings != 2 {
			t.Errorf("AdjustedFindings = %d, want 2", rep.Summary.FP.AdjustedFindings)
		}
		if rep.Summary.FP.ByReason["FP_GITLAB_CI_FLAG"] != 1 {
			t.Errorf("ByReason[FP_GITLAB_CI_FLAG] = %d, want 1", rep.Summary.FP.ByReason["FP_GITLAB_CI_FLAG"])
		}
		if rep.Summary.FP.ByReason["FP_PAGES_ARTIFACTS"] != 1 {
			t.Errorf("ByReason[FP_PAGES_ARTIFACTS] = %d, want 1", rep.Summary.FP.ByReason["FP_PAGES_ARTIFACTS"])
		}
		// Severity counts should exclude FP findings
		if rep.Summary.BySeverity[analyze.SeverityHigh] != 2 {
			t.Errorf("HIGH = %d, want 2", rep.Summary.BySeverity[analyze.SeverityHigh])
		}
		if rep.Summary.BySeverity[analyze.SeverityMedium] != 0 {
			t.Errorf("MEDIUM = %d, want 0 (FP filtered)", rep.Summary.BySeverity[analyze.SeverityMedium])
		}
		if rep.Summary.BySeverity[analyze.SeverityLow] != 0 {
			t.Errorf("LOW = %d, want 0 (FP filtered)", rep.Summary.BySeverity[analyze.SeverityLow])
		}
	})
}

func TestRenderText_IncludesRecommendation(t *testing.T) {
	in := []enumerate.Result{{
		ProjectID:         1,
		ProjectPathWithNS: "g/proj",
		WebURL:            "https://gitlab.com/g/proj",
		HasCIPipeline:     true,
		CISummary:         "jobs=2",
		Findings: []analyze.Finding{{
			ID:             "INCLUDE_REMOTE",
			Severity:       analyze.SeverityHigh,
			Title:          "Remote include in pipeline",
			Recommendation: "Avoid remote includes; prefer project includes pinned to a commit.",
		}},
	}}
	rep := Build(in, Options{})
	var buf bytes.Buffer
	if err := RenderText(&buf, rep, ""); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Recommendation:") {
		t.Fatalf("expected text report to contain 'Recommendation:', got:\n%s", out)
	}
	if !strings.Contains(out, "Avoid remote includes") {
		t.Fatalf("expected text report to contain recommendation text, got:\n%s", out)
	}
}
