package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

func TestLoadFromFile_JSONL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "results.jsonl")

	results := []enumerate.Result{
		{ProjectID: 1, ProjectPathWithNS: "g/a", Findings: []analyze.Finding{{ID: "X", Severity: analyze.SeverityHigh}}},
		{ProjectID: 2, ProjectPathWithNS: "g/b"},
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadFromFile(p)
	if err != nil {
		t.Fatalf("loadFromFile: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0].ProjectPathWithNS != "g/a" {
		t.Errorf("result[0].PathWithNS = %q, want %q", got[0].ProjectPathWithNS, "g/a")
	}
	if len(got[0].Findings) != 1 {
		t.Errorf("result[0] findings = %d, want 1", len(got[0].Findings))
	}
}

func TestLoadFromFile_JSONArray(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "results.json")

	results := []enumerate.Result{
		{ProjectID: 10, ProjectPathWithNS: "x/y", HasCIPipeline: true},
	}
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadFromFile(p)
	if err != nil {
		t.Fatalf("loadFromFile: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].ProjectID != 10 {
		t.Errorf("ProjectID = %d, want 10", got[0].ProjectID)
	}
}

func TestLoadFromFile_JSONArrayWithLeadingWhitespace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "results.json")

	results := []enumerate.Result{
		{ProjectID: 5, ProjectPathWithNS: "a/b"},
	}
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	// Prepend whitespace and newlines
	content := "\n  \t" + string(data)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadFromFile(p)
	if err != nil {
		t.Fatalf("loadFromFile: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
}

func TestLoadFromFile_Empty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := loadFromFile(p)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestStoreToResults(t *testing.T) {
	ers := []store.EnumerateResult{
		{
			GitLabProjectID:   100,
			PathWithNamespace: "org/proj",
			WebURL:            "https://gitlab.com/org/proj",
			DefaultBranch:     "main",
			HasCIPipeline:     true,
			RunnersTotal:      3,
			RunnersOnline:     1,
			DurationMS:        500,
			Error:             "some warning",
			Findings: []store.Finding{
				{FindingID: "INCLUDE_REMOTE", Severity: "HIGH", Title: "Remote include", Evidence: "https://x.com/ci.yml", JobName: "build", Recommendation: "Pin it"},
				{FindingID: "ARTIFACTS_NO_EXPIRE", Severity: "LOW", Title: "No expire"},
			},
		},
		{
			GitLabProjectID:   200,
			PathWithNamespace: "org/proj2",
		},
	}

	got := storeToResults(ers)
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}

	r := got[0]
	if r.ProjectID != 100 {
		t.Errorf("ProjectID = %d, want 100", r.ProjectID)
	}
	if r.ProjectPathWithNS != "org/proj" {
		t.Errorf("Path = %q, want %q", r.ProjectPathWithNS, "org/proj")
	}
	if !r.HasCIPipeline {
		t.Error("expected HasCIPipeline=true")
	}
	if r.RunnersTotal != 3 {
		t.Errorf("RunnersTotal = %d, want 3", r.RunnersTotal)
	}
	if r.Error != "some warning" {
		t.Errorf("Error = %q, want %q", r.Error, "some warning")
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(r.Findings))
	}
	if r.Findings[0].ID != "INCLUDE_REMOTE" {
		t.Errorf("finding[0].ID = %q, want %q", r.Findings[0].ID, "INCLUDE_REMOTE")
	}
	if r.Findings[0].Severity != analyze.SeverityHigh {
		t.Errorf("finding[0].Severity = %q, want %q", r.Findings[0].Severity, analyze.SeverityHigh)
	}
	if r.Findings[0].JobName != "build" {
		t.Errorf("finding[0].JobName = %q, want %q", r.Findings[0].JobName, "build")
	}
	if r.Findings[0].Recommendation != "Pin it" {
		t.Errorf("finding[0].Recommendation = %q, want %q", r.Findings[0].Recommendation, "Pin it")
	}

	// Second result has no findings
	if len(got[1].Findings) != 0 {
		t.Errorf("result[1] findings = %d, want 0", len(got[1].Findings))
	}
}

func TestReport_FromJSONL_HTMLOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "results.jsonl")
	out := filepath.Join(dir, "report.html")

	results := []enumerate.Result{
		{ProjectID: 1, ProjectPathWithNS: "g/proj", WebURL: "https://gl.com/g/proj", HasCIPipeline: true,
			Findings: []analyze.Finding{{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh, Title: "Remote include"}}},
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(in, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	reportInput = in
	reportOutputPath = out
	reportFormat = "html"
	reportOnlyFindings = false

	if err := reportCmd.RunE(reportCmd, nil); err != nil {
		t.Fatalf("report RunE: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "GoGatoZ Security Report") {
		t.Error("expected report header")
	}
	if !strings.Contains(html, "INCLUDE_REMOTE") {
		t.Error("expected finding ID in report")
	}
	if !strings.Contains(html, "g/proj") {
		t.Error("expected project path in report")
	}
}

func TestReport_DefaultFormatIsHTML(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "results.jsonl")
	out := filepath.Join(dir, "report.html")

	if err := os.WriteFile(in, []byte(`{"project_id":1,"path_with_namespace":"a/b"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reportInput = in
	reportOutputPath = out
	reportFormat = "" // empty should default to html

	if err := reportCmd.RunE(reportCmd, nil); err != nil {
		t.Fatalf("report RunE: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Error("expected HTML output as default format")
	}
}
