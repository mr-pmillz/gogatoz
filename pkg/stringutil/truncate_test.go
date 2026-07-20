package stringutil

import "testing"

func TestTruncateEvidence(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{"empty", "", 10, ""},
		{"short", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"truncate", "hello world", 8, "hello..."},
		{"zero max", "hello", 0, "hello"},
		{"negative max", "hello", -1, "hello"},
		{"max 3", "hello", 3, "hel"},
		{"max 2", "hello", 2, "he"},
		{"unicode", "héllo wörld", 8, "héllo..."},
		{"unicode exact", "héllo", 5, "héllo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateEvidence(tt.s, tt.max)
			if got != tt.want {
				t.Errorf("TruncateEvidence(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}
