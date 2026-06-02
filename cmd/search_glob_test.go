package cmd

import (
	"testing"
)

func TestGlobToRegex_Basics(t *testing.T) {
	tests := []struct {
		glob string
		ok   []string
		bad  []string
	}{
		{"*.yml", []string{"a.yml", "b.yml"}, []string{"a.yaml", "dir/a.yml", "a.yml/"}},
		{"**/*.yml", []string{"a.yml", "dir/a.yml", "x/y/z.yml"}, []string{"a.yaml", "dir/a.yaml"}},
		{"ci/**/config?.yml", []string{"ci/config1.yml", "ci/x/config2.yml"}, []string{"ci/config12.yml", "ci/x/config/.yml"}},
		{".gitlab-ci.yml", []string{".gitlab-ci.yml"}, []string{"x/.gitlab-ci.yml", ".gitlab-ci.yml.bak"}},
	}
	for i, tc := range tests {
		r, err := globToRegex(tc.glob)
		if err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}
		for _, s := range tc.ok {
			if !r.MatchString(s) {
				t.Fatalf("case %d: expected %q to match %q", i, tc.glob, s)
			}
		}
		for _, s := range tc.bad {
			if r.MatchString(s) {
				t.Fatalf("case %d: expected %q NOT to match %q", i, tc.glob, s)
			}
		}
	}
}

func TestGlobToRegex_EmptyError(t *testing.T) {
	if _, err := globToRegex(""); err == nil {
		t.Fatalf("expected error on empty glob")
	}
}
