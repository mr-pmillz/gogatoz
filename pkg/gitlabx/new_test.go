package gitlabx

import (
	"testing"
)

func TestNormalizeBaseURL_Variants(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{"gitlab.example.com", "https://gitlab.example.com"},
		{"https://gitlab.example.com/", "https://gitlab.example.com"},
		{"https://gitlab.example.com/api/v4", "https://gitlab.example.com"},
		{"https://gitlab.example.com/api/v4/", "https://gitlab.example.com"},
		{"https://gitlab.example.com/gitlab", "https://gitlab.example.com/gitlab"},
		{"https://gitlab.example.com/gitlab/", "https://gitlab.example.com/gitlab"},
		{"https://gitlab.example.com/gitlab/api", "https://gitlab.example.com/gitlab"},
		{"https://gitlab.example.com/gitlab/api/v4", "https://gitlab.example.com/gitlab"},
		{"https://gitlab.example.com/gitlab/api/v4/", "https://gitlab.example.com/gitlab"},
	}
	for i, c := range cases {
		got, err := normalizeBaseURL(c.in)
		if err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}
		if got != c.out {
			t.Fatalf("case %d: normalize %q => %q, want %q", i, c.in, got, c.out)
		}
	}
}

func TestNew_NormalizesBaseURL(t *testing.T) {
	cl, err := New("https://gitlab.internal.local/api/v4/", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if cl.baseURL != "https://gitlab.internal.local" {
		t.Fatalf("unexpected baseURL: %q", cl.baseURL)
	}
}
