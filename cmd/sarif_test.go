package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

func TestBuildSARIF_MixedSeverities(t *testing.T) {
	findings := []analyze.Finding{
		{
			ID:          "PLAINTEXT_SECRET",
			Severity:    analyze.SeverityMedium,
			Title:       "Suspicious plaintext variable",
			Description: "Variable looks secret-like",
			Evidence:    "TOKEN=abc123",
			JobName:     "build",
		},
		{
			ID:          "SELF_HOSTED_EXPOSED",
			Severity:    analyze.SeverityHigh,
			Title:       "Job on tagged runner with broad triggers",
			Description: "Runner exposure risk",
			Evidence:    "tags: [shell]",
			JobName:     "deploy",
		},
		{
			ID:          "WORKFLOW_BROAD_RULES",
			Severity:    analyze.SeverityInformational,
			Title:       "Workflow has broad rules",
			Description: "Broad workflow rules",
		},
	}

	s := buildSARIF(findings, "1.0.0")

	if len(s.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(s.Runs))
	}
	run := s.Runs[0]

	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}

	// Verify severity mapping per result.
	wantLevels := map[string]string{
		"PLAINTEXT_SECRET":     "warning",
		"SELF_HOSTED_EXPOSED":  "error",
		"WORKFLOW_BROAD_RULES": "note",
	}
	for _, res := range run.Results {
		want, ok := wantLevels[res.RuleID]
		if !ok {
			t.Errorf("unexpected ruleId %q", res.RuleID)
			continue
		}
		if res.Level != want {
			t.Errorf("ruleId %q: level = %q, want %q", res.RuleID, res.Level, want)
		}
	}
}

func TestBuildSARIF_SchemaAndVersion(t *testing.T) {
	s := buildSARIF(nil, "2.0.0")

	if s.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", s.Version, "2.1.0")
	}
	wantSchema := "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	if s.Schema != wantSchema {
		t.Errorf("schema = %q, want %q", s.Schema, wantSchema)
	}

	if len(s.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(s.Runs))
	}
	drv := s.Runs[0].Tool.Driver
	if drv.Name != "GoGatoZ" {
		t.Errorf("driver name = %q, want %q", drv.Name, "GoGatoZ")
	}
	if drv.InformationURI != "https://github.com/mr-pmillz/gogatoz" {
		t.Errorf("informationUri = %q", drv.InformationURI)
	}
	if drv.Version != "2.0.0" {
		t.Errorf("driver version = %q, want %q", drv.Version, "2.0.0")
	}
}

func TestBuildSARIF_SecuritySeverityProperties(t *testing.T) {
	findings := []analyze.Finding{
		{ID: "RUNNER_EXECUTOR_RISK", Severity: analyze.SeverityCritical, Title: "t", Description: "d"},
		{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityHigh, Title: "t", Description: "d"},
		{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "t", Description: "d"},
	}

	s := buildSARIF(findings, "1.0.0")
	run := s.Runs[0]

	wantSS := map[string]string{
		"RUNNER_EXECUTOR_RISK": "9.5",
		"SELF_HOSTED_EXPOSED":  "8.0",
		"PLAINTEXT_SECRET":     "5.0",
	}

	for _, rule := range run.Tool.Driver.Rules {
		want, ok := wantSS[rule.ID]
		if !ok {
			continue
		}
		got, exists := rule.Properties["security-severity"]
		if !exists {
			t.Errorf("rule %q missing security-severity property", rule.ID)
			continue
		}
		if got != want {
			t.Errorf("rule %q security-severity = %v, want %q", rule.ID, got, want)
		}
	}
}

func TestBuildSARIF_EmptyFindings(t *testing.T) {
	s := buildSARIF(nil, "dev")

	if len(s.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(s.Runs))
	}
	run := s.Runs[0]

	if run.Tool.Driver.Rules != nil {
		t.Errorf("expected nil rules, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Results != nil {
		t.Errorf("expected nil results, got %d", len(run.Results))
	}

	// Verify it marshals to valid JSON.
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil, "dev"); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}
	var decoded sarifLog
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestBuildSARIF_DedupRulesMultipleResults(t *testing.T) {
	findings := []analyze.Finding{
		{
			ID:       "VARIABLE_INJECTION",
			Severity: analyze.SeverityMedium,
			Title:    "Unsafe CI variable usage",
			Evidence: "CI_COMMIT_MESSAGE in build job",
			JobName:  "build",
		},
		{
			ID:       "VARIABLE_INJECTION",
			Severity: analyze.SeverityMedium,
			Title:    "Unsafe CI variable usage",
			Evidence: "CI_MERGE_REQUEST_TITLE in test job",
			JobName:  "test",
		},
	}

	s := buildSARIF(findings, "1.0.0")
	run := s.Runs[0]

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule (deduped), got %d", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "VARIABLE_INJECTION" {
		t.Errorf("rule ID = %q, want %q", run.Tool.Driver.Rules[0].ID, "VARIABLE_INJECTION")
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	// Verify each result has distinct evidence in the message.
	if run.Results[0].Message.Text == run.Results[1].Message.Text {
		t.Error("expected distinct messages for the two results")
	}
}

func TestBuildSARIF_SkipsEmptyID(t *testing.T) {
	findings := []analyze.Finding{
		{ID: "", Severity: analyze.SeverityLow, Title: "no id"},
		{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "t", Evidence: "e"},
	}

	s := buildSARIF(findings, "1.0.0")
	run := s.Runs[0]

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule (skip empty ID), got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
}

func TestBuildSARIF_FallbackMessageToDescription(t *testing.T) {
	findings := []analyze.Finding{
		{
			ID:          "SELF_HOSTED_EXPOSED",
			Severity:    analyze.SeverityHigh,
			Title:       "Job on tagged runner",
			Description: "Runner exposure risk",
			// Evidence intentionally empty.
		},
	}

	s := buildSARIF(findings, "1.0.0")
	run := s.Runs[0]

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	if run.Results[0].Message.Text != "Runner exposure risk" {
		t.Errorf("message = %q, want description fallback", run.Results[0].Message.Text)
	}
}

func TestBuildSARIF_LocationIsGitlabCI(t *testing.T) {
	findings := []analyze.Finding{
		{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "t", Evidence: "e"},
	}

	s := buildSARIF(findings, "1.0.0")
	run := s.Runs[0]

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	locs := run.Results[0].Locations
	if len(locs) != 1 {
		t.Fatalf("expected 1 location, got %d", len(locs))
	}
	uri := locs[0].PhysicalLocation.ArtifactLocation.URI
	if uri != ".gitlab-ci.yml" {
		t.Errorf("artifact URI = %q, want %q", uri, ".gitlab-ci.yml")
	}
}

func TestWriteSARIF_ProducesValidJSON(t *testing.T) {
	findings := []analyze.Finding{
		{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "t", Evidence: "e"},
		{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityHigh, Title: "t", Evidence: "e"},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "3.0.0"); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var decoded sarifLog
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if decoded.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", decoded.Version, "2.1.0")
	}
	if len(decoded.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results after round-trip, got %d", len(decoded.Runs[0].Results))
	}
}

func TestSarifLevel(t *testing.T) {
	cases := []struct {
		sev  analyze.Severity
		want string
	}{
		{analyze.SeverityCritical, "error"},
		{analyze.SeverityHigh, "error"},
		{analyze.SeverityMedium, "warning"},
		{analyze.SeverityLow, "note"},
		{analyze.SeverityInformational, "note"},
	}
	for _, tc := range cases {
		got := sarifLevel(tc.sev)
		if got != tc.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestSarifSecuritySeverity(t *testing.T) {
	cases := []struct {
		sev  analyze.Severity
		want string
	}{
		{analyze.SeverityCritical, "9.5"},
		{analyze.SeverityHigh, "8.0"},
		{analyze.SeverityMedium, "5.0"},
		{analyze.SeverityLow, "2.0"},
		{analyze.SeverityInformational, "1.0"},
	}
	for _, tc := range cases {
		got := sarifSecuritySeverity(tc.sev)
		if got != tc.want {
			t.Errorf("sarifSecuritySeverity(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestBuildSARIF_RegistryMetadata(t *testing.T) {
	// Verify that when a finding ID is in the registry, rule metadata comes
	// from the registry rather than the finding itself.
	findings := []analyze.Finding{
		{
			ID:          "PLAINTEXT_SECRET",
			Severity:    analyze.SeverityMedium,
			Title:       "override title",
			Description: "override desc",
		},
	}

	s := buildSARIF(findings, "1.0.0")
	rule := s.Runs[0].Tool.Driver.Rules[0]

	info := analyze.LookupFinding("PLAINTEXT_SECRET")
	if info == nil {
		t.Fatal("PLAINTEXT_SECRET not in registry")
	}
	if rule.ShortDescription.Text != info.Title {
		t.Errorf("shortDescription = %q, want registry title %q", rule.ShortDescription.Text, info.Title)
	}
	if rule.FullDescription == nil || rule.FullDescription.Text != info.Description {
		t.Errorf("fullDescription = %v, want registry description", rule.FullDescription)
	}
}
