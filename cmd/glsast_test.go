package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

func TestBuildGLSAST_VulnerabilityCount(t *testing.T) {
	findings := []analyze.Finding{
		{ID: "VARIABLE_INJECTION", Severity: analyze.SeverityMedium, Title: "Unsafe CI variable", JobName: "build"},
		{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh, Title: "Remote include", JobName: "deploy"},
		{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "Plaintext secret", JobName: "test"},
	}
	report := buildGLSAST(findings, "1.0.0", time.Now(), time.Now())
	if len(report.Vulnerabilities) != 3 {
		t.Fatalf("expected 3 vulnerabilities, got %d", len(report.Vulnerabilities))
	}
}

func TestBuildGLSAST_SeverityMapping(t *testing.T) {
	tests := []struct {
		input analyze.Severity
		want  string
	}{
		{analyze.SeverityCritical, "Critical"},
		{analyze.SeverityHigh, "High"},
		{analyze.SeverityMedium, "Medium"},
		{analyze.SeverityLow, "Low"},
		{analyze.SeverityInformational, "Info"},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			findings := []analyze.Finding{
				{ID: "TEST", Severity: tt.input, Title: "test", JobName: "job"},
			}
			report := buildGLSAST(findings, "1.0.0", time.Now(), time.Now())
			got := report.Vulnerabilities[0].Severity
			if got != tt.want {
				t.Errorf("mapSeverity(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildGLSAST_StableID(t *testing.T) {
	f := analyze.Finding{
		ID:       "VARIABLE_INJECTION",
		Severity: analyze.SeverityMedium,
		Title:    "Unsafe CI variable",
		Evidence: "script uses $CI_COMMIT_MESSAGE",
		JobName:  "build",
	}

	id1 := vulnID(f)
	id2 := vulnID(f)
	if id1 != id2 {
		t.Fatalf("vulnID not stable: %q != %q", id1, id2)
	}

	// verify it matches manual SHA-256
	h := sha256.Sum256([]byte(f.ID + "|" + f.JobName + "|" + f.Evidence))
	want := fmt.Sprintf("%x", h)
	if id1 != want {
		t.Fatalf("vulnID = %q, want SHA-256 %q", id1, want)
	}

	// different evidence must produce different ID
	f2 := f
	f2.Evidence = "different evidence"
	if vulnID(f2) == id1 {
		t.Fatal("different findings should have different IDs")
	}
}

func TestBuildGLSAST_ScannerMetadata(t *testing.T) {
	report := buildGLSAST(nil, "2.5.0", time.Now(), time.Now())

	if report.Scan.Scanner.ID != "gogatoz" {
		t.Errorf("scanner ID = %q, want %q", report.Scan.Scanner.ID, "gogatoz")
	}
	if report.Scan.Scanner.Name != "GoGatoZ" {
		t.Errorf("scanner name = %q, want %q", report.Scan.Scanner.Name, "GoGatoZ")
	}
	if report.Scan.Scanner.Version != "2.5.0" {
		t.Errorf("scanner version = %q, want %q", report.Scan.Scanner.Version, "2.5.0")
	}
	if report.Scan.Scanner.Vendor.Name != "mr-pmillz" {
		t.Errorf("scanner vendor = %q, want %q", report.Scan.Scanner.Vendor.Name, "mr-pmillz")
	}
	if report.Scan.Analyzer.ID != "gogatoz" {
		t.Errorf("analyzer ID = %q, want %q", report.Scan.Analyzer.ID, "gogatoz")
	}
	if report.Scan.Type != "sast" {
		t.Errorf("scan type = %q, want %q", report.Scan.Type, "sast")
	}
	if report.Scan.Status != "success" {
		t.Errorf("scan status = %q, want %q", report.Scan.Status, "success")
	}
}

func TestBuildGLSAST_EmptyFindings(t *testing.T) {
	report := buildGLSAST(nil, "1.0.0", time.Now(), time.Now())
	if report.Vulnerabilities == nil {
		t.Fatal("vulnerabilities should be empty slice, not nil")
		return
	}
	if len(report.Vulnerabilities) != 0 {
		t.Fatalf("expected 0 vulnerabilities, got %d", len(report.Vulnerabilities))
	}
}

func TestBuildGLSAST_SchemaVersion(t *testing.T) {
	report := buildGLSAST(nil, "1.0.0", time.Now(), time.Now())
	if report.Version != "15.0.4" {
		t.Errorf("schema version = %q, want %q", report.Version, "15.0.4")
	}
}

func TestBuildGLSAST_VulnFields(t *testing.T) {
	f := analyze.Finding{
		ID:             "INCLUDE_REMOTE",
		Severity:       analyze.SeverityHigh,
		Title:          "Remote include in pipeline",
		Description:    "Pipeline includes a remote URL",
		Evidence:       "include: https://evil.com/ci.yml",
		JobName:        "deploy",
		Recommendation: "Use project includes instead",
	}
	report := buildGLSAST([]analyze.Finding{f}, "1.0.0", time.Now(), time.Now())
	v := report.Vulnerabilities[0]

	if v.Name != f.Title {
		t.Errorf("name = %q, want %q", v.Name, f.Title)
	}
	wantDesc := f.Evidence + "\n\n" + f.Description
	if v.Description != wantDesc {
		t.Errorf("description = %q, want %q", v.Description, wantDesc)
	}
	if v.Solution != f.Recommendation {
		t.Errorf("solution = %q, want %q", v.Solution, f.Recommendation)
	}
	if v.Location.File != ".gitlab-ci.yml" {
		t.Errorf("location file = %q, want %q", v.Location.File, ".gitlab-ci.yml")
	}
	if len(v.Identifiers) != 1 {
		t.Fatalf("expected 1 identifier, got %d", len(v.Identifiers))
	}
	if v.Identifiers[0].Type != "gogatoz_finding_id" {
		t.Errorf("identifier type = %q, want %q", v.Identifiers[0].Type, "gogatoz_finding_id")
	}
	if v.Identifiers[0].Value != f.ID {
		t.Errorf("identifier value = %q, want %q", v.Identifiers[0].Value, f.ID)
	}
	if v.Scanner.ID != "gogatoz" {
		t.Errorf("vuln scanner id = %q, want %q", v.Scanner.ID, "gogatoz")
	}
}

func TestBuildGLSAST_SolutionFallsBackToRegistry(t *testing.T) {
	f := analyze.Finding{
		ID:       "INCLUDE_REMOTE",
		Severity: analyze.SeverityHigh,
		Title:    "Remote include",
		JobName:  "job",
		// Recommendation intentionally empty to trigger registry lookup
	}
	report := buildGLSAST([]analyze.Finding{f}, "1.0.0", time.Now(), time.Now())
	v := report.Vulnerabilities[0]

	info := analyze.LookupFinding("INCLUDE_REMOTE")
	if info == nil {
		t.Fatal("INCLUDE_REMOTE not found in registry")
		return
	}
	if v.Solution != info.Remediation {
		t.Errorf("solution = %q, want registry remediation %q", v.Solution, info.Remediation)
	}
}

func TestBuildGLSAST_ScanTimes(t *testing.T) {
	start := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	end := time.Date(2025, 6, 15, 10, 31, 45, 0, time.UTC)

	report := buildGLSAST(nil, "1.0.0", start, end)

	wantStart := "2025-06-15T10:30:00Z"
	wantEnd := "2025-06-15T10:31:45Z"
	if report.Scan.StartTime != wantStart {
		t.Errorf("start_time = %q, want %q", report.Scan.StartTime, wantStart)
	}
	if report.Scan.EndTime != wantEnd {
		t.Errorf("end_time = %q, want %q", report.Scan.EndTime, wantEnd)
	}
}

func TestWriteGLSAST_ValidJSON(t *testing.T) {
	findings := []analyze.Finding{
		{ID: "TEST", Severity: analyze.SeverityLow, Title: "test finding", JobName: "job"},
	}
	var buf bytes.Buffer
	if err := WriteGLSAST(&buf, findings, "1.0.0", time.Now(), time.Now()); err != nil {
		t.Fatalf("WriteGLSAST error: %v", err)
	}

	var report glsastReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if report.Version != glsastSchemaVersion {
		t.Errorf("version = %q, want %q", report.Version, glsastSchemaVersion)
	}
	if len(report.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(report.Vulnerabilities))
	}
}

func TestVulnDescription_EvidenceOnly(t *testing.T) {
	f := analyze.Finding{Evidence: "some evidence"}
	got := vulnDescription(f)
	if got != "some evidence" {
		t.Errorf("vulnDescription = %q, want %q", got, "some evidence")
	}
}

func TestVulnDescription_DescriptionOnly(t *testing.T) {
	f := analyze.Finding{Description: "some description"}
	got := vulnDescription(f)
	if got != "some description" {
		t.Errorf("vulnDescription = %q, want %q", got, "some description")
	}
}
