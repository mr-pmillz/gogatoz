package report

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestGenerateRecommendations_CIInjection(t *testing.T) {
	results := []enumerate.Result{{
		ProjectPathWithNS: "org/vuln-project",
		HasCIPipeline:     true,
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityCritical,
			JobName:  "build",
		}},
	}}
	recs := GenerateRecommendations(results)
	found := false
	for _, r := range recs {
		if r.Category == "CI Injection" {
			found = true
			if len(r.Projects) == 0 {
				t.Error("expected projects in CI Injection recommendation")
			}
		}
	}
	if !found {
		t.Error("expected CI Injection recommendation for SELF_HOSTED_EXPOSED finding")
	}
}

func TestGenerateRecommendations_SupplyChain(t *testing.T) {
	results := []enumerate.Result{{
		ProjectPathWithNS: "org/cache-proj",
		HasCIPipeline:     true,
		Findings: []analyze.Finding{{
			ID:       "CACHE_POISONING_RISK",
			Severity: analyze.SeverityHigh,
		}},
	}}
	recs := GenerateRecommendations(results)
	found := false
	for _, r := range recs {
		if r.Category == "Supply Chain" {
			found = true
		}
	}
	if !found {
		t.Error("expected Supply Chain recommendation for cache poisoning finding")
	}
}

func TestGenerateRecommendations_NoFindings(t *testing.T) {
	results := []enumerate.Result{{
		ProjectPathWithNS: "org/clean",
		HasCIPipeline:     true,
	}}
	recs := GenerateRecommendations(results)
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for clean project, got %d", len(recs))
	}
}

func TestGenerateRecommendations_MultipleCategories(t *testing.T) {
	results := []enumerate.Result{{
		ProjectPathWithNS: "org/multi",
		HasCIPipeline:     true,
		Findings: []analyze.Finding{
			{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityCritical},
			{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityHigh},
			{ID: "FORK_MR_SELF_HOSTED", Severity: analyze.SeverityHigh},
		},
	}}
	recs := GenerateRecommendations(results)
	if len(recs) < 2 {
		t.Errorf("expected multiple recommendation categories, got %d", len(recs))
	}
}

func TestGenerateRecommendations_FalsePositivesSkipped(t *testing.T) {
	results := []enumerate.Result{{
		ProjectPathWithNS: "org/fp-only",
		HasCIPipeline:     true,
		Findings: []analyze.Finding{{
			ID:            "SELF_HOSTED_EXPOSED",
			Severity:      analyze.SeverityCritical,
			FalsePositive: true,
		}},
	}}
	recs := GenerateRecommendations(results)
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations when all findings are false positives, got %d", len(recs))
	}
}

func TestGenerateRecommendations_DeduplicatesProjects(t *testing.T) {
	results := []enumerate.Result{{
		ProjectPathWithNS: "org/dup",
		HasCIPipeline:     true,
		Findings: []analyze.Finding{
			{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityCritical},
			{ID: "MR_TAGGED_RUNNER", Severity: analyze.SeverityHigh},
		},
	}}
	recs := GenerateRecommendations(results)
	for _, r := range recs {
		if r.Category == "CI Injection" {
			if len(r.Projects) != 1 {
				t.Errorf("expected 1 deduplicated project for CI Injection, got %d", len(r.Projects))
			}
		}
	}
}

func TestGenerateRecommendations_CommandFormat(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "org/first",
			HasCIPipeline:     true,
			Findings:          []analyze.Finding{{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityHigh}},
		},
		{
			ProjectPathWithNS: "org/second",
			HasCIPipeline:     true,
			Findings:          []analyze.Finding{{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityHigh}},
		},
	}
	recs := GenerateRecommendations(results)
	for _, r := range recs {
		if r.Category == "Secrets Exfiltration" {
			if r.Command == "" {
				t.Error("expected non-empty command for Secrets Exfiltration")
			}
			if len(r.Projects) != 2 {
				t.Errorf("expected 2 projects for Secrets Exfiltration, got %d", len(r.Projects))
			}
		}
	}
}
