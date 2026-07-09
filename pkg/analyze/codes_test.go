package analyze

import "testing"

func TestLookupFinding(t *testing.T) {
	info := LookupFinding("VARIABLE_INJECTION")
	if info == nil {
		t.Fatal("expected VARIABLE_INJECTION to be registered")
	}
	if info.Title == "" {
		t.Error("expected non-empty title")
	}
	if info.Remediation == "" {
		t.Error("expected non-empty remediation")
	}
}

func TestLookupFinding_unknown(t *testing.T) {
	info := LookupFinding("DOES_NOT_EXIST_99999")
	if info != nil {
		t.Fatalf("expected nil for unknown code, got %+v", info)
	}
}

func TestAllFindings_sorted(t *testing.T) {
	all := AllFindings()
	if len(all) == 0 {
		t.Fatal("expected at least one registered finding")
	}
	for i := 1; i < len(all); i++ {
		if all[i].ID < all[i-1].ID {
			t.Errorf("findings not sorted: %s comes after %s", all[i].ID, all[i-1].ID)
		}
	}
}

func TestAllFindings_count(t *testing.T) {
	all := AllFindings()
	// 26 finding IDs registered (23 original + RUNNER_EXECUTOR_RISK + supply chain constants)
	if len(all) < 23 {
		t.Errorf("expected at least 23 registered findings, got %d", len(all))
	}
}

func TestAllFindings_fields(t *testing.T) {
	for _, info := range AllFindings() {
		if info.ID == "" {
			t.Error("finding has empty ID")
		}
		if info.Severity == "" {
			t.Errorf("finding %s has empty severity", info.ID)
		}
		if info.Title == "" {
			t.Errorf("finding %s has empty title", info.ID)
		}
		if info.Description == "" {
			t.Errorf("finding %s has empty description", info.ID)
		}
		if info.Remediation == "" {
			t.Errorf("finding %s has empty remediation", info.ID)
		}
	}
}

func TestWithRecommendations_uses_registry(t *testing.T) {
	findings := []Finding{
		{ID: "VARIABLE_INJECTION"},
		{ID: "UNKNOWN_CODE_XYZ"},
	}
	result := withRecommendations(findings)

	info := LookupFinding("VARIABLE_INJECTION")
	if info == nil {
		t.Fatal("VARIABLE_INJECTION should be in registry")
	}
	if result[0].Recommendation != info.Remediation {
		t.Errorf("expected recommendation from registry, got %q", result[0].Recommendation)
	}
	if result[1].Recommendation != defaultRemediation {
		t.Errorf("expected default remediation for unknown code, got %q", result[1].Recommendation)
	}
}

func TestWithRecommendations_preserves_existing(t *testing.T) {
	custom := "custom recommendation"
	findings := []Finding{
		{ID: "VARIABLE_INJECTION", Recommendation: custom},
	}
	result := withRecommendations(findings)
	if result[0].Recommendation != custom {
		t.Errorf("expected existing recommendation to be preserved, got %q", result[0].Recommendation)
	}
}
