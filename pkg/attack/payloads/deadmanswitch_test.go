package payloads

import (
	"strings"
	"testing"
)

func TestGenerateDeadManSwitchYAML(t *testing.T) {
	tests := []struct {
		name         string
		opts         DeadManSwitchOptions
		wantContains []string
	}{
		{
			name: "linux systemd defaults",
			opts: DeadManSwitchOptions{
				Common: CommonOptions{Tags: []string{"shell"}},
			},
			wantContains: []string{
				"systemd",
				"dms-monitor.service",
				"dms-monitor.timer",
				"dms-cleanup",
				"echo token-revoked",
				"https://gitlab.com/api/v4/user",
				"systemctl --user",
			},
		},
		{
			name: "macos LaunchAgent",
			opts: DeadManSwitchOptions{
				Common:   CommonOptions{JobName: "dms-mac"},
				Platform: "macos",
			},
			wantContains: []string{
				"LaunchAgent",
				"com.dms.monitor.plist",
				"KeepAlive",
				"SuccessfulExit",
				"launchctl load",
				"Library/LaunchAgents",
			},
		},
		{
			name: "custom handler",
			opts: DeadManSwitchOptions{
				Common:  CommonOptions{JobName: "dms-custom"},
				Handler: "curl -sS http://backup.invalid/alert",
			},
			wantContains: []string{
				"curl -sS http://backup.invalid/alert",
				"systemd",
			},
		},
		{
			name: "custom TTL and interval",
			opts: DeadManSwitchOptions{
				Common:        CommonOptions{JobName: "dms-ttl", Tags: []string{"runner"}},
				CheckInterval: "30",
				TTL:           "3600",
				MonitorURL:    "https://gitlab.local/api/v4/user",
			},
			wantContains: []string{
				"30s",
				"3600s",
				"https://gitlab.local/api/v4/user",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateDeadManSwitchYAML(tt.opts)
			for _, substr := range tt.wantContains {
				if !strings.Contains(y, substr) {
					t.Errorf("expected %q in output:\n%s", substr, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
