package enumerate

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestClassifyJobProtection(t *testing.T) {
	tests := []struct {
		name              string
		job               pipeline.Job
		protectedBranches []string
		want              ProtectionLevel
	}{
		{
			name: "structural: rules gate on CI_COMMIT_REF_PROTECTED true",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{map[string]any{
					"if":   `$CI_COMMIT_REF_PROTECTED == "true"`,
					"when": "on_success",
				}},
			},
			want: ProtectionStructural,
		},
		{
			name: "structural: only protected keyword",
			job: pipeline.Job{
				Name: "deploy",
				Only: []any{"protected"},
			},
			want: ProtectionStructural,
		},
		{
			name: "structural: only.refs protected",
			job: pipeline.Job{
				Name: "deploy",
				Only: map[string]any{"refs": []any{"protected"}},
			},
			want: ProtectionStructural,
		},
		{
			name: "branch-gated: rules gate to main which is protected",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{map[string]any{
					"if": `$CI_COMMIT_BRANCH == "main"`,
				}},
			},
			protectedBranches: []string{"main"},
			want:              ProtectionBranchGated,
		},
		{
			name: "heuristic: rules mention protected but not structural",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{map[string]any{
					"if": `$SOME_VAR == "protected"`,
				}},
			},
			want: ProtectionHeuristic,
		},
		{
			name: "none: broad rules no protection",
			job: pipeline.Job{
				Name:  "deploy",
				Rules: []any{map[string]any{"when": "always"}},
			},
			want: ProtectionNone,
		},
		{
			name: "none: no rules at all",
			job: pipeline.Job{
				Name: "deploy",
			},
			want: ProtectionNone,
		},
		{
			name: "none: always-run rule overrides structural",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{
					map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "true"`},
					map[string]any{"when": "always"},
				},
			},
			want: ProtectionNone,
		},
		{
			name: "none: no protected branches for branch gate",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{map[string]any{
					"if": `$CI_COMMIT_BRANCH == "main"`,
				}},
			},
			protectedBranches: nil,
			want:              ProtectionNone,
		},
		{
			name: "branch-gated: multiple protected branches all match",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{
					map[string]any{"if": `$CI_COMMIT_BRANCH == "main"`},
					map[string]any{"if": `$CI_COMMIT_BRANCH == "release"`},
				},
			},
			protectedBranches: []string{"main", "release"},
			want:              ProtectionBranchGated,
		},
		{
			name: "branch-gated: extra non-protected branch still passes gate check",
			job: pipeline.Job{
				Name: "build",
				Rules: []any{
					map[string]any{"if": `$CI_COMMIT_BRANCH == "main"`},
					map[string]any{"if": `$CI_COMMIT_BRANCH == "develop"`},
				},
			},
			protectedBranches: []string{"main"},
			// The branch-gate check verifies all protected branches match and a
			// synthetic unprotected branch does not. "develop" is not tested
			// because it is not in protectedBranches. This is an accepted limitation.
			want: ProtectionBranchGated,
		},
		{
			name: "structural: CI_COMMIT_REF_PROTECTED with != false",
			job: pipeline.Job{
				Name: "deploy",
				Rules: []any{map[string]any{
					"if": `$CI_COMMIT_REF_PROTECTED != "false"`,
				}},
			},
			want: ProtectionStructural,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyJobProtection(tt.job, tt.protectedBranches)
			if got != tt.want {
				t.Errorf("classifyJobProtection() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestJobHasAlwaysRule(t *testing.T) {
	tests := []struct {
		name  string
		rules any
		want  bool
	}{
		{
			name:  "nil rules",
			rules: nil,
			want:  false,
		},
		{
			name:  "when always",
			rules: []any{map[string]any{"when": "always"}},
			want:  true,
		},
		{
			name:  "when on_success",
			rules: []any{map[string]any{"when": "on_success"}},
			want:  true,
		},
		{
			name:  "empty when defaults to on_success",
			rules: []any{map[string]any{}},
			want:  true,
		},
		{
			name:  "has if clause with when always — not unconditional",
			rules: []any{map[string]any{"if": `$CI_COMMIT_BRANCH == "main"`, "when": "always"}},
			want:  false,
		},
		{
			name:  "when never",
			rules: []any{map[string]any{"when": "never"}},
			want:  false,
		},
		{
			name:  "when manual",
			rules: []any{map[string]any{"when": "manual"}},
			want:  false,
		},
		{
			name:  "string type (not array)",
			rules: "always",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jobHasAlwaysRule(tt.rules)
			if got != tt.want {
				t.Errorf("jobHasAlwaysRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdjustFindings_StructuralDowngrade(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name: "deploy",
			Rules: []any{map[string]any{
				"if":   `$CI_COMMIT_REF_PROTECTED == "true"`,
				"when": "on_success",
			}},
		}},
	}
	r := Result{
		Findings: []analyze.Finding{
			{
				ID:       "MR_TAGGED_RUNNER",
				Severity: analyze.SeverityHigh,
				JobName:  "deploy",
				Evidence: "tags=[build]",
			},
			{
				ID:       "SELF_HOSTED_EXPOSED",
				Severity: analyze.SeverityMedium,
				JobName:  "deploy",
				Evidence: "runner exposed",
			},
		},
	}
	adjustFindingsForProtectedBranches(&r, doc)

	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Errorf("expected HIGH→MEDIUM structural downgrade, got %s", got)
	}
	if !strings.Contains(r.Findings[0].Evidence, "[gated: CI_COMMIT_REF_PROTECTED]") {
		t.Errorf("expected structural evidence annotation, got %q", r.Findings[0].Evidence)
	}

	if got := r.Findings[1].Severity; got != analyze.SeverityLow {
		t.Errorf("expected MEDIUM→LOW structural downgrade, got %s", got)
	}
	if !strings.Contains(r.Findings[1].Evidence, "[gated: CI_COMMIT_REF_PROTECTED]") {
		t.Errorf("expected structural evidence annotation, got %q", r.Findings[1].Evidence)
	}
}

func TestAdjustFindings_HeuristicOnlyDowngradesHigh(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name: "build",
			Rules: []any{map[string]any{
				"if": `$SOME_VAR == "protected"`,
			}},
		}},
	}
	rHigh := Result{
		Findings: []analyze.Finding{{
			ID:       "MR_TAGGED_RUNNER",
			Severity: analyze.SeverityHigh,
			JobName:  "build",
		}},
	}
	adjustFindingsForProtectedBranches(&rHigh, doc)
	if got := rHigh.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Errorf("heuristic: expected HIGH→MEDIUM, got %s", got)
	}
	if !strings.Contains(rHigh.Findings[0].Evidence, "[heuristic:") {
		t.Errorf("expected heuristic evidence annotation, got %q", rHigh.Findings[0].Evidence)
	}

	rMed := Result{
		Findings: []analyze.Finding{{
			ID:       "MR_TAGGED_RUNNER",
			Severity: analyze.SeverityMedium,
			JobName:  "build",
		}},
	}
	adjustFindingsForProtectedBranches(&rMed, doc)
	if got := rMed.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Errorf("heuristic: expected MEDIUM to stay MEDIUM, got %s", got)
	}
}

func TestAdjustFindings_BranchGatedWithAPIData(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name: "deploy",
			Rules: []any{map[string]any{
				"if": `$CI_COMMIT_BRANCH == "main"`,
			}},
		}},
	}
	r := Result{
		ProtectedBranches: []string{"main"},
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityHigh,
			JobName:  "deploy",
			Evidence: "runner on self-hosted",
		}},
	}
	adjustFindingsForProtectedBranches(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Errorf("expected HIGH→MEDIUM branch-gated downgrade, got %s", got)
	}
	if !strings.Contains(r.Findings[0].Evidence, "[gated: branch-restricted to protected branches]") {
		t.Errorf("expected branch-gated evidence annotation, got %q", r.Findings[0].Evidence)
	}
}

func TestAdjustFindingsForProtectedBranches_Downgrades(t *testing.T) {
	// Build a minimal pipeline document with one protected job
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name: "build",
			Only: []any{"protected"},
		}},
	}
	// Result has a runner-related finding tied to that job
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "MR_TAGGED_RUNNER",
			Severity: analyze.SeverityHigh,
			JobName:  "build",
		}},
	}
	adjustFindingsForProtectedBranches(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Fatalf("expected severity to be downgraded to MEDIUM, got %s", got)
	}
}

func TestAdjustFindings_NilAndEmptyInputs(t *testing.T) {
	// nil result — should not panic
	adjustFindingsForProtectedBranches(nil, &pipeline.Document{})

	// nil doc — should not panic
	r := Result{Findings: []analyze.Finding{{ID: "MR_TAGGED_RUNNER", Severity: analyze.SeverityHigh, JobName: "x"}}}
	adjustFindingsForProtectedBranches(&r, nil)
	if r.Findings[0].Severity != analyze.SeverityHigh {
		t.Error("expected no change with nil doc")
	}

	// no findings — should not panic
	r2 := Result{}
	adjustFindingsForProtectedBranches(&r2, &pipeline.Document{Jobs: []pipeline.Job{{Name: "x", Only: []any{"protected"}}}})

	// no jobs — should not panic
	r3 := Result{Findings: []analyze.Finding{{ID: "MR_TAGGED_RUNNER", Severity: analyze.SeverityHigh, JobName: "x"}}}
	adjustFindingsForProtectedBranches(&r3, &pipeline.Document{})
	if r3.Findings[0].Severity != analyze.SeverityHigh {
		t.Error("expected no change with empty jobs")
	}
}

func TestAdjustFindings_NonEligibleFindingNotDowngraded(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name: "deploy",
			Only: []any{"protected"},
		}},
	}
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "VARIABLE_INJECTION",
			Severity: analyze.SeverityHigh,
			JobName:  "deploy",
		}},
	}
	adjustFindingsForProtectedBranches(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityHigh {
		t.Errorf("non-eligible finding should not be downgraded, got %s", got)
	}
}

func TestIsProtectionEligible(t *testing.T) {
	eligible := []string{
		"SELF_HOSTED_EXPOSED",
		"SELF_HOSTED_EXPOSED_TAGS",
		"MR_TAGGED_RUNNER",
		"PRIVILEGED_RUNNER_RISK",
		"PWN_REQUEST_DEPLOYMENT",
		"RUNNER_EXECUTOR_RISK",
	}
	for _, id := range eligible {
		if !isProtectionEligible(id) {
			t.Errorf("expected %q to be protection-eligible", id)
		}
	}

	ineligible := []string{
		"VARIABLE_INJECTION",
		"ARTIFACT_POISONING",
		"PLAINTEXT_SECRET",
		"",
	}
	for _, id := range ineligible {
		if isProtectionEligible(id) {
			t.Errorf("expected %q to NOT be protection-eligible", id)
		}
	}
}

func TestDowngradeSeverity(t *testing.T) {
	tests := []struct {
		in   analyze.Severity
		want analyze.Severity
	}{
		{analyze.SeverityHigh, analyze.SeverityMedium},
		{analyze.SeverityMedium, analyze.SeverityLow},
		{analyze.SeverityLow, analyze.SeverityLow},
	}
	for _, tt := range tests {
		got := downgradeSeverity(tt.in)
		if got != tt.want {
			t.Errorf("downgradeSeverity(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestRulesGateOnRefProtected(t *testing.T) {
	tests := []struct {
		name  string
		rules any
		want  bool
	}{
		{
			name: "gates on protected true",
			rules: []any{map[string]any{
				"if": `$CI_COMMIT_REF_PROTECTED == "true"`,
			}},
			want: true,
		},
		{
			name: "not gated: matches both protected and unprotected",
			rules: []any{
				map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "true"`},
				map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "false"`},
			},
			want: false,
		},
		{
			name: "when never on unprotected match is ok",
			rules: []any{
				map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "true"`, "when": "on_success"},
				map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "false"`, "when": "never"},
			},
			want: true,
		},
		{
			name:  "nil rules",
			rules: nil,
			want:  false,
		},
		{
			name:  "empty array",
			rules: []any{},
			want:  false,
		},
		{
			name: "no if expression",
			rules: []any{map[string]any{
				"when": "always",
			}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rulesGateOnRefProtected(tt.rules)
			if got != tt.want {
				t.Errorf("rulesGateOnRefProtected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOnlyContainsProtected(t *testing.T) {
	tests := []struct {
		name string
		only any
		want bool
	}{
		{"array with protected", []any{"protected"}, true},
		{"array case insensitive", []any{"Protected"}, true},
		{"map refs protected", map[string]any{"refs": []any{"protected"}}, true},
		{"string protected", "protected", true},
		{"array without protected", []any{"tags"}, false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := onlyContainsProtected(tt.only)
			if got != tt.want {
				t.Errorf("onlyContainsProtected() = %v, want %v", got, tt.want)
			}
		})
	}
}
