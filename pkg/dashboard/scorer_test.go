package dashboard

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestScoreProject(t *testing.T) {
	tests := []struct {
		name     string
		result   enumerate.Result
		wantTier string
		wantMin  int
		wantMax  int
	}{
		{
			name: "clean_project",
			result: enumerate.Result{
				ProjectPathWithNS: "group/clean",
				HasCIPipeline:     true,
				ProtectedBranches: []string{"main"},
			},
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
		{
			name: "critical_findings_two",
			result: enumerate.Result{
				ProjectPathWithNS: "group/vuln",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "TEST", Severity: analyze.SeverityCritical},
					{ID: "TEST2", Severity: analyze.SeverityCritical},
				},
			},
			// 100 - 2*15 = 70
			wantTier: "Low",
			wantMin:  61,
			wantMax:  80,
		},
		{
			name: "many_criticals_reach_critical_tier",
			result: enumerate.Result{
				ProjectPathWithNS: "group/vuln-many",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "C1", Severity: analyze.SeverityCritical},
					{ID: "C2", Severity: analyze.SeverityCritical},
					{ID: "C3", Severity: analyze.SeverityCritical},
					{ID: "C4", Severity: analyze.SeverityCritical},
					{ID: "C5", Severity: analyze.SeverityCritical},
					{ID: "C6", Severity: analyze.SeverityCritical},
				},
			},
			// 100 - 6*15 = 10
			wantTier: "Critical",
			wantMin:  0,
			wantMax:  20,
		},
		{
			name: "medium_findings",
			result: enumerate.Result{
				ProjectPathWithNS: "group/med",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "T1", Severity: analyze.SeverityMedium},
					{ID: "T2", Severity: analyze.SeverityMedium},
					{ID: "T3", Severity: analyze.SeverityMedium},
				},
			},
			// 100 - 3*3 = 91
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
		{
			name: "no_ci",
			result: enumerate.Result{
				ProjectPathWithNS: "group/noci",
				HasCIPipeline:     false,
			},
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
		{
			name: "false_positives_excluded",
			result: enumerate.Result{
				ProjectPathWithNS: "group/fp",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "FP1", Severity: analyze.SeverityCritical, FalsePositive: true},
					{ID: "REAL", Severity: analyze.SeverityLow},
				},
			},
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
		{
			name: "floor_at_zero",
			result: enumerate.Result{
				ProjectPathWithNS: "group/terrible",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "C1", Severity: analyze.SeverityCritical},
					{ID: "C2", Severity: analyze.SeverityCritical},
					{ID: "C3", Severity: analyze.SeverityCritical},
					{ID: "C4", Severity: analyze.SeverityCritical},
					{ID: "C5", Severity: analyze.SeverityCritical},
					{ID: "C6", Severity: analyze.SeverityCritical},
					{ID: "C7", Severity: analyze.SeverityCritical},
					{ID: "C8", Severity: analyze.SeverityCritical},
				},
			},
			wantTier: "Critical",
			wantMin:  0,
			wantMax:  0,
		},
		{
			name: "security_job_bonus",
			result: enumerate.Result{
				ProjectPathWithNS: "group/secjobs",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "T1", Severity: analyze.SeverityMedium, JobName: "sast-scan"},
				},
			},
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := ScoreProject(tt.result)
			if sc.Score < tt.wantMin || sc.Score > tt.wantMax {
				t.Errorf("score = %d, want [%d, %d]", sc.Score, tt.wantMin, tt.wantMax)
			}
			if sc.RiskTier != tt.wantTier {
				t.Errorf("tier = %s, want %s", sc.RiskTier, tt.wantTier)
			}
		})
	}
}
