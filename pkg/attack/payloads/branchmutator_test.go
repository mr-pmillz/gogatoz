package payloads

import (
	"strings"
	"testing"
)

func TestGenerateBranchMutatorYAML(t *testing.T) {
	tests := []struct {
		name         string
		opts         BranchMutatorOptions
		wantContains []string
	}{
		{
			name: "default options",
			opts: BranchMutatorOptions{
				Common: CommonOptions{Tags: []string{"shell"}},
			},
			wantContains: []string{
				"repository/branches",
				"repository/commits",
				".gitlab-ci.yml",
				"chore: update configuration",
				"Branch mutator",
				"branch-mutator:",
			},
		},
		{
			name: "custom file and content",
			opts: BranchMutatorOptions{
				Common:      CommonOptions{JobName: "mutate", Stage: "persist"},
				FilePath:    "README.md",
				FileContent: "# pwned",
				CallbackURL: "http://attacker.com/callback",
			},
			wantContains: []string{
				"repository/branches",
				"repository/commits",
				"README.md",
				"# pwned",
				"mutate:",
				"stage: persist",
				"http://attacker.com/callback",
			},
		},
		{
			name: "max branches set",
			opts: BranchMutatorOptions{
				Common:      CommonOptions{JobName: "spread"},
				MaxBranches: 25,
			},
			wantContains: []string{
				"repository/branches",
				"repository/commits",
				"_max=25",
			},
		},
		{
			name: "manual rule and image",
			opts: BranchMutatorOptions{
				Common: CommonOptions{
					JobName: "stealth",
					Image:   "alpine:latest",
					Manual:  true,
				},
				CommitMessage: "fix: apply patch",
			},
			wantContains: []string{
				"repository/branches",
				"repository/commits",
				"image: alpine:latest",
				"when: manual",
				"fix: apply patch",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateBranchMutatorYAML(tt.opts)
			for _, substr := range tt.wantContains {
				if !strings.Contains(y, substr) {
					t.Errorf("expected %q in output:\n%s", substr, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
