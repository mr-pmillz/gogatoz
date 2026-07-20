package enumerate

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

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

func hasFinding(findings []analyze.Finding, id string) bool { //nolint:unused // test helper for future tests
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}
