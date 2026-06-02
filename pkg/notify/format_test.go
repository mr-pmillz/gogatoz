package notify

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestFormatDiscordMessages_NoFindings(t *testing.T) {
	results := []enumerate.Result{
		{ProjectPathWithNS: "ns/project-a"},
		{ProjectPathWithNS: "ns/project-b"},
	}
	msgs := FormatDiscordMessages(results)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Type != TypeSuccess {
		t.Errorf("expected type success, got %s", msgs[0].Type)
	}
	if len(msgs[0].Embeds) != 1 {
		t.Fatalf("expected 1 embed (summary), got %d", len(msgs[0].Embeds))
	}
	if !strings.Contains(msgs[0].Embeds[0].Description, "2") {
		t.Error("summary should mention 2 projects")
	}
}

func TestFormatDiscordMessages_WithFindings(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "ns/vuln-project",
			Findings: []analyze.Finding{
				{ID: "VARIABLE_INJECTION", Severity: analyze.SeverityHigh, Title: "var injection", Evidence: "echo $CI_MR_TITLE", JobName: "build"},
				{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "secret in config"},
			},
		},
	}
	msgs := FormatDiscordMessages(results)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Type != TypeFailure {
		t.Errorf("expected type failure (has HIGH), got %s", msgs[0].Type)
	}
	// 1 summary + 2 findings = 3 embeds
	if len(msgs[0].Embeds) != 3 {
		t.Fatalf("expected 3 embeds, got %d", len(msgs[0].Embeds))
	}
	// Summary embed
	if msgs[0].Embeds[0].Color != ColorHigh {
		t.Errorf("summary color should be red, got %d", msgs[0].Embeds[0].Color)
	}
	// Finding embeds
	if msgs[0].Embeds[1].Color != ColorHigh {
		t.Errorf("HIGH finding color should be red, got %d", msgs[0].Embeds[1].Color)
	}
	if msgs[0].Embeds[2].Color != ColorMedium {
		t.Errorf("MEDIUM finding color should be orange, got %d", msgs[0].Embeds[2].Color)
	}
}

func TestFormatDiscordMessages_Chunking(t *testing.T) {
	var findings []analyze.Finding
	for i := range 15 {
		findings = append(findings, analyze.Finding{
			ID:       "RULE_" + string(rune('A'+i)),
			Severity: analyze.SeverityLow,
			Title:    "test finding",
		})
	}
	results := []enumerate.Result{
		{ProjectPathWithNS: "ns/big-project", Findings: findings},
	}
	msgs := FormatDiscordMessages(results)
	// 1 summary + 15 findings = 16 embeds → 2 messages (10 + 6)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if len(msgs[0].Embeds) != 10 {
		t.Errorf("first message should have 10 embeds, got %d", len(msgs[0].Embeds))
	}
	if len(msgs[1].Embeds) != 6 {
		t.Errorf("second message should have 6 embeds, got %d", len(msgs[1].Embeds))
	}
}

func TestFormatAppriseMarkdown_NoFindings(t *testing.T) {
	results := []enumerate.Result{
		{ProjectPathWithNS: "ns/clean"},
	}
	msg := FormatAppriseMarkdown(results)
	if msg.Type != TypeSuccess {
		t.Errorf("expected type success, got %s", msg.Type)
	}
	if !strings.Contains(msg.Body, "No findings") {
		t.Error("body should mention no findings")
	}
	if !strings.Contains(msg.Body, "1") {
		t.Error("body should mention 1 project")
	}
}

func TestFormatAppriseMarkdown_WithFindings(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "ns/vuln",
			Findings: []analyze.Finding{
				{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh, Title: "insecure include", Evidence: "https://example.com/ci.yml"},
				{ID: "ARTIFACTS_NO_EXPIRE", Severity: analyze.SeverityLow, Title: "no expiry"},
			},
		},
	}
	msg := FormatAppriseMarkdown(results)
	if msg.Type != TypeFailure {
		t.Errorf("expected type failure (has HIGH), got %s", msg.Type)
	}
	if !strings.Contains(msg.Body, "### ") {
		t.Error("body should contain severity section headers")
	}
	if !strings.Contains(msg.Body, "INCLUDE_REMOTE") {
		t.Error("body should contain finding ID")
	}
	if !strings.Contains(msg.Body, "`ns/vuln`") {
		t.Error("body should contain project name")
	}
}

func TestFormatAppriseMarkdown_MediumOnly(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "ns/med",
			Findings: []analyze.Finding{
				{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "secret"},
			},
		},
	}
	msg := FormatAppriseMarkdown(results)
	if msg.Type != TypeWarning {
		t.Errorf("expected type warning (only MEDIUM), got %s", msg.Type)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"this is too long", 10, "this is..."},
		{"ab", 2, "ab"},
		{"abc", 2, "ab"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}
