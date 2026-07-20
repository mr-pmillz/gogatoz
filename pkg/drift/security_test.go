package drift

import "testing"

func TestAssessSecurityImpact(t *testing.T) {
	tests := []struct {
		name       string
		changes    []Change
		wantSev    string
		wantMinLen int
	}{
		{
			name: "security_job_removed",
			changes: []Change{
				{Type: ChangeRemoved, Category: CategoryJob, Name: "sast-scan"},
			},
			wantSev:    "CRITICAL",
			wantMinLen: 1,
		},
		{
			name: "remote_include_added",
			changes: []Change{
				{Type: ChangeAdded, Category: CategoryInclude, Name: "remote:https://evil.com/ci.yml"},
			},
			wantSev:    "HIGH",
			wantMinLen: 1,
		},
		{
			name: "script_changed",
			changes: []Change{
				{Type: ChangeModified, Category: CategoryScript, Name: "deploy"},
			},
			wantSev:    "MEDIUM",
			wantMinLen: 1,
		},
		{
			name: "variable_added",
			changes: []Change{
				{Type: ChangeAdded, Category: CategoryVariable, Name: "NEW_VAR"},
			},
			wantSev:    "LOW",
			wantMinLen: 1,
		},
		{
			name:       "no_changes",
			changes:    nil,
			wantMinLen: 0,
		},
		{
			name: "include_removed",
			changes: []Change{
				{Type: ChangeRemoved, Category: CategoryInclude, Name: "local:.ci/lint.yml"},
			},
			wantSev:    "MEDIUM",
			wantMinLen: 1,
		},
		{
			name: "variable_removed",
			changes: []Change{
				{Type: ChangeRemoved, Category: CategoryVariable, Name: "OLD_VAR"},
			},
			wantSev:    "LOW",
			wantMinLen: 1,
		},
		{
			name: "non_security_job_removed",
			changes: []Change{
				{Type: ChangeRemoved, Category: CategoryJob, Name: "format-code"},
			},
			wantMinLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssessSecurityImpact(tt.changes)
			if len(got) < tt.wantMinLen {
				t.Errorf("expected at least %d security changes, got %d", tt.wantMinLen, len(got))
			}
			if tt.wantSev != "" && len(got) > 0 {
				if string(got[0].Severity) != tt.wantSev {
					t.Errorf("expected severity %s, got %s", tt.wantSev, got[0].Severity)
				}
			}
		})
	}
}

func TestIsSecurityJob(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"sast-scan", true},
		{"DAST_analysis", true},
		{"secret-detection", true},
		{"container_scan_job", true},
		{"trivy-check", true},
		{"gosec-lint", true},
		{"build", false},
		{"deploy", false},
		{"format-code", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSecurityJob(tt.name); got != tt.want {
				t.Errorf("isSecurityJob(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
