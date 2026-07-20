package stringutil

import "testing"

func TestQuoteJoin(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"normal slice", []string{"a", "b", "c"}, `"a", "b", "c"`},
		{"trimmed whitespace", []string{" a ", " b "}, `"a", "b"`},
		{"single element", []string{"only"}, `"only"`},
		{"empty slice", []string{}, ""},
		{"nil slice", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := QuoteJoin(tt.in)
			if got != tt.want {
				t.Fatalf("QuoteJoin(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
