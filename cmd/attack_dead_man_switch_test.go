package cmd

import "testing"

func TestDeadManSwitchMonitorURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured string
		base       string
		want       string
	}{
		{name: "self hosted default", base: "http://gitlab.local:8929/", want: "http://gitlab.local:8929/api/v4/user"},
		{name: "explicit override", configured: "https://monitor.invalid/check", base: "http://gitlab.local:8929", want: "https://monitor.invalid/check"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := deadManSwitchMonitorURL(tt.configured, tt.base); got != tt.want {
				t.Fatalf("deadManSwitchMonitorURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
