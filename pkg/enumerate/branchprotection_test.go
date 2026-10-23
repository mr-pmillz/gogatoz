package enumerate

import "testing"

func TestAccessLevelName(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{0, "no_access"},
		{30, "developer"},
		{40, "maintainer"},
		{60, "admin"},
		{99, "unknown"},
	}
	for _, tt := range tests {
		got := accessLevelName(tt.level)
		if got != tt.want {
			t.Errorf("accessLevelName(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}
