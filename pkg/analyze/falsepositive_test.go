package analyze

import "testing"

func TestApplyFPRules(t *testing.T) {
	tests := []struct {
		name     string
		finding  Finding
		wantFP   bool
		wantRule string
	}{
		{
			name:     "gitlab_ci_flag_secret_detection_enabled",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "SECRET_DETECTION_ENABLED=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_historic",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "SECRET_DETECTION_HISTORIC_ENABLED=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_mr_pipelines",
			finding:  Finding{ID: "PLAINTEXT_SECRET_JOB", Evidence: "SECRET_DETECTION_ENABLE_MR_PIPELINES=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_sast_disabled",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "SAST_DISABLED=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_ds_excluded",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "DS_EXCLUDED_ANALYZERS=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_code_quality",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "CODE_QUALITY_DISABLED=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_container_scanning",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "CONTAINER_SCANNING_DISABLED=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_dependency_scanning",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "DEPENDENCY_SCANNING_DISABLED=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:     "gitlab_ci_flag_case_insensitive",
			finding:  Finding{ID: "PLAINTEXT_SECRET", Evidence: "secret_detection_enabled=<redacted>"},
			wantFP:   true,
			wantRule: "FP_GITLAB_CI_FLAG",
		},
		{
			name:    "real_secret_not_filtered",
			finding: Finding{ID: "PLAINTEXT_SECRET", Evidence: "MY_API_KEY=<redacted>"},
			wantFP:  false,
		},
		{
			name:    "wrong_finding_id_not_filtered",
			finding: Finding{ID: "INCLUDE_REMOTE", Evidence: "SECRET_DETECTION_ENABLED=<redacted>"},
			wantFP:  false,
		},
		{
			name:     "pages_artifacts_match",
			finding:  Finding{ID: "ARTIFACTS_NO_EXPIRE", JobName: "pages", Evidence: `"public"`},
			wantFP:   true,
			wantRule: "FP_PAGES_ARTIFACTS",
		},
		{
			name:     "pages_artifacts_case_insensitive",
			finding:  Finding{ID: "ARTIFACTS_NO_EXPIRE", JobName: "Pages"},
			wantFP:   true,
			wantRule: "FP_PAGES_ARTIFACTS",
		},
		{
			name:    "artifacts_not_pages_job",
			finding: Finding{ID: "ARTIFACTS_NO_EXPIRE", JobName: "build"},
			wantFP:  false,
		},
		{
			name:    "unrelated_finding_not_filtered",
			finding: Finding{ID: "INCLUDE_REMOTE", Evidence: "https://example.com/ci.yml"},
			wantFP:  false,
		},
	}

	rules := DefaultFPRules()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ApplyFPRules([]Finding{tt.finding}, rules)
			if len(result) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(result))
			}
			if result[0].FalsePositive != tt.wantFP {
				t.Errorf("FalsePositive = %v, want %v", result[0].FalsePositive, tt.wantFP)
			}
			if tt.wantFP && result[0].FalsePositiveReason != tt.wantRule {
				t.Errorf("FalsePositiveReason = %q, want %q", result[0].FalsePositiveReason, tt.wantRule)
			}
		})
	}
}

func TestApplyFPRules_immutability(t *testing.T) {
	original := []Finding{
		{ID: "PLAINTEXT_SECRET", Evidence: "SECRET_DETECTION_ENABLED=<redacted>"},
	}
	result := ApplyFPRules(original, DefaultFPRules())

	if original[0].FalsePositive {
		t.Error("original slice was mutated")
	}
	if !result[0].FalsePositive {
		t.Error("result should have FalsePositive=true")
	}
}

func TestFilterTruePositives(t *testing.T) {
	findings := []Finding{
		{ID: "PLAINTEXT_SECRET", FalsePositive: true},
		{ID: "INCLUDE_REMOTE"},
		{ID: "ARTIFACTS_NO_EXPIRE", FalsePositive: true},
		{ID: "VARIABLE_INJECTION"},
	}

	filtered := FilterTruePositives(findings)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 true positives, got %d", len(filtered))
	}
	if filtered[0].ID != "INCLUDE_REMOTE" {
		t.Errorf("filtered[0].ID = %q, want INCLUDE_REMOTE", filtered[0].ID)
	}
	if filtered[1].ID != "VARIABLE_INJECTION" {
		t.Errorf("filtered[1].ID = %q, want VARIABLE_INJECTION", filtered[1].ID)
	}
}

func TestFilterTruePositives_empty(t *testing.T) {
	filtered := FilterTruePositives(nil)
	if len(filtered) != 0 {
		t.Errorf("expected 0, got %d", len(filtered))
	}
}

func TestDefaultFPRules_count(t *testing.T) {
	rules := DefaultFPRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}
