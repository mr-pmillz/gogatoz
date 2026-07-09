package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectIncludeForbiddenVersion(t *testing.T) {
	tests := []struct {
		name    string
		doc     *pipeline.Document
		wantID  bool
		wantLen int
	}{
		{
			name: "branch ref main triggers finding",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "infra/ci-templates",
						Ref:     "main",
						File:    []string{"/templates/sast.yml"},
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "branch ref master triggers finding",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "infra/ci-templates",
						Ref:     "master",
						File:    []string{"/templates/build.yml"},
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "branch ref develop case-insensitive",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "org/shared",
						Ref:     "Develop",
						File:    []string{"/ci.yml"},
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "tag ref v1.2.3 does not trigger",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "infra/ci-templates",
						Ref:     "v1.2.3",
						File:    []string{"/templates/sast.yml"},
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
		{
			name: "commit SHA does not trigger",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "infra/ci-templates",
						Ref:     "abc123def456789012345678",
						File:    []string{"/templates/deploy.yml"},
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
		{
			name: "empty ref does not trigger (caught by INCLUDE_PROJECT_UNPINNED)",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "infra/ci-templates",
						File:    []string{"/templates/sast.yml"},
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
		{
			name: "non-project include type ignored",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:   pipeline.IncludeRemote,
						Remote: "https://example.com/ci.yml",
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
		{
			name: "branch ref staging triggers finding",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "ops/deploy",
						Ref:     "staging",
						File:    []string{"/deploy.yml"},
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "custom branch name does not trigger",
			doc: &pipeline.Document{
				Includes: []pipeline.Include{
					{
						Type:    pipeline.IncludeProject,
						Project: "infra/ci-templates",
						Ref:     "feature/new-pipeline",
						File:    []string{"/ci.yml"},
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectIncludeForbiddenVersion(tt.doc)
			if len(findings) != tt.wantLen {
				t.Fatalf("expected %d findings, got %d", tt.wantLen, len(findings))
			}
			if tt.wantID && !hasFindingID(findings, IncludeForbiddenVersionID) {
				t.Fatalf("expected finding %s not found", IncludeForbiddenVersionID)
			}
			if !tt.wantID && hasFindingID(findings, IncludeForbiddenVersionID) {
				t.Fatalf("unexpected finding %s found", IncludeForbiddenVersionID)
			}
		})
	}
}

func TestDetectSecurityJobWeakened(t *testing.T) {
	tests := []struct {
		name    string
		doc     *pipeline.Document
		wantID  bool
		wantLen int
	}{
		{
			name: "SAST job with allow_failure triggers finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name:         "sast-scan",
						AllowFailure: true,
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "secret-detection job with when manual triggers finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name: "secret-detection",
						When: "manual",
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "security job with rules when never triggers finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name: "container_scanning",
						Rules: []any{
							map[string]any{"when": "never"},
						},
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "regular job with allow_failure does not trigger",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name:         "build",
						AllowFailure: true,
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
		{
			name: "security job without weakening does not trigger",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name:         "dependency_scanning",
						AllowFailure: false,
						When:         "on_success",
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
		{
			name: "DAST job with multiple weakenings produces one finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name:         "dast-full-scan",
						AllowFailure: true,
						When:         "manual",
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "code_quality job with when manual triggers finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name: "code_quality",
						When: "manual",
					},
				},
			},
			wantID:  true,
			wantLen: 1,
		},
		{
			name: "license_scanning job no weakening no finding",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{
					{
						Name: "license_scanning",
					},
				},
			},
			wantID:  false,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectSecurityJobWeakened(tt.doc)
			if len(findings) != tt.wantLen {
				t.Fatalf("expected %d findings, got %d", tt.wantLen, len(findings))
			}
			if tt.wantID && !hasFindingID(findings, SecurityJobWeakenedID) {
				t.Fatalf("expected finding %s not found", SecurityJobWeakenedID)
			}
			if !tt.wantID && hasFindingID(findings, SecurityJobWeakenedID) {
				t.Fatalf("unexpected finding %s found", SecurityJobWeakenedID)
			}
		})
	}
}

func TestDetectSecurityJobWeakenedSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{
				Name:         "sast",
				AllowFailure: true,
			},
		},
	}
	findings := detectSecurityJobWeakened(doc)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Fatalf("expected severity %s, got %s", SeverityCritical, findings[0].Severity)
	}
}

func TestDetectGovernanceNilDoc(t *testing.T) {
	findings := detectGovernance(nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for nil doc, got %d", len(findings))
	}
}

func TestDetectJobHardcodedStub(t *testing.T) {
	doc := &pipeline.Document{
		Includes: []pipeline.Include{
			{Type: pipeline.IncludeProject, Project: "infra/templates", Ref: "v1.0.0"},
		},
		Jobs: []pipeline.Job{
			{Name: "build"},
		},
	}
	findings := detectJobHardcoded(doc)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings from stub, got %d", len(findings))
	}
}

func TestIsSecurityJob(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"sast-scan", true},
		{"my-sast", true},
		{"secret-detection", true},
		{"dast-full-scan", true},
		{"container_scanning", true},
		{"dependency_scanning", true},
		{"license_scanning", true},
		{"code_quality", true},
		{"security-audit", true},
		{"build", false},
		{"deploy", false},
		{"test", false},
		{"lint", false},
		{"SAST-Scan", true}, // case-insensitive
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSecurityJob(tt.name)
			if got != tt.want {
				t.Fatalf("isSecurityJob(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsForbiddenBranchRef(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"main", true},
		{"master", true},
		{"develop", true},
		{"dev", true},
		{"staging", true},
		{"production", true},
		{"release", true},
		{"Main", true},    // case-insensitive
		{"MASTER", true},  // case-insensitive
		{"v1.2.3", false}, // tag
		{"abc123", false}, // short sha
		{"feature/x", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := isForbiddenBranchRef(tt.ref)
			if got != tt.want {
				t.Fatalf("isForbiddenBranchRef(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestRulesContainWhenNever(t *testing.T) {
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
			name: "rules with when never",
			rules: []any{
				map[string]any{"when": "never"},
			},
			want: true,
		},
		{
			name: "rules with when always",
			rules: []any{
				map[string]any{"when": "always"},
			},
			want: false,
		},
		{
			name: "rules with when on_success",
			rules: []any{
				map[string]any{"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'", "when": "on_success"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rulesContainWhenNever(tt.rules)
			if got != tt.want {
				t.Fatalf("rulesContainWhenNever() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectGovernanceIntegration(t *testing.T) {
	doc := &pipeline.Document{
		Includes: []pipeline.Include{
			{
				Type:    pipeline.IncludeProject,
				Project: "shared/ci",
				Ref:     "main",
				File:    []string{"/sast.yml"},
			},
		},
		Jobs: []pipeline.Job{
			{
				Name:         "sast",
				AllowFailure: true,
			},
			{
				Name: "build",
				When: "on_success",
			},
		},
	}
	findings := detectGovernance(doc, nil)

	if !hasFindingID(findings, IncludeForbiddenVersionID) {
		t.Fatalf("expected %s finding", IncludeForbiddenVersionID)
	}
	if !hasFindingID(findings, SecurityJobWeakenedID) {
		t.Fatalf("expected %s finding", SecurityJobWeakenedID)
	}
	// build job is not a security job, should not produce SECURITY_JOB_WEAKENED
	for _, f := range findings {
		if f.ID == SecurityJobWeakenedID && f.JobName == "build" {
			t.Fatalf("build job should not produce %s", SecurityJobWeakenedID)
		}
	}
}
