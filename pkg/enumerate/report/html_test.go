package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func buildTestReport(onlyFindings bool) Report {
	results := []enumerate.Result{
		{
			ProjectID:         1,
			ProjectPathWithNS: "group/proj-a",
			WebURL:            "https://gitlab.com/group/proj-a",
			HasCIPipeline:     true,
			CISummary:         "jobs=3",
			Findings: []analyze.Finding{
				{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh, Title: "Remote include", Evidence: "include: https://example.com/ci.yml", Recommendation: "Pin to commit SHA"},
				{ID: "VARIABLE_INJECTION", Severity: analyze.SeverityMedium, Title: "Variable injection", JobName: "deploy", Evidence: "echo $CI_MERGE_REQUEST_TITLE"},
			},
		},
		{
			ProjectID:         2,
			ProjectPathWithNS: "group/proj-b",
			WebURL:            "https://gitlab.com/group/proj-b",
			HasCIPipeline:     true,
			CISummary:         "jobs=1",
			Findings: []analyze.Finding{
				{ID: "ARTIFACTS_NO_EXPIRE", Severity: analyze.SeverityLow, Title: "Artifacts no expire"},
			},
		},
		{
			ProjectID:         3,
			ProjectPathWithNS: "group/proj-c",
			WebURL:            "https://gitlab.com/group/proj-c",
			HasCIPipeline:     true,
			CISummary:         "jobs=2",
		},
		{
			ProjectID:         4,
			ProjectPathWithNS: "group/proj-d",
			WebURL:            "https://gitlab.com/group/proj-d",
			HasCIPipeline:     true,
			CISummary:         "jobs=2",
			RunnerTagHits:     map[string]int{"docker": 1, "shell_exec": 2},
			Findings: []analyze.Finding{
				{ID: "SELF_HOSTED_EXPOSED", Severity: analyze.SeverityHigh, Title: "Job on tagged runner", Evidence: "tags=[shell_exec docker]"},
				{ID: "PLAINTEXT_SECRET", Severity: analyze.SeverityMedium, Title: "Suspicious plaintext variable", Evidence: "MY_TOKEN=<redacted>"},
			},
		},
	}
	return Build(results, Options{OnlyFindings: onlyFindings})
}

func renderHTML(t *testing.T, r Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderHTML(&buf, r, "v0.0.0-test"); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	return buf.String()
}

func TestRenderHTML_ContainsCharts(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	for _, want := range []string{
		`id="chartSeverity"`,
		`id="chartTypes"`,
		`id="chartInfra"`,
		"new Chart(",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q", want)
		}
	}
}

func TestRenderHTML_DataTables(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	for _, want := range []string{
		`id="projectsTable"`,
		`id="findingsTable"`,
		"$('#projectsTable').DataTable(",
		"$('#findingsTable').DataTable(",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q", want)
		}
	}
}

func TestRenderHTML_SeverityBadges(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	if !strings.Contains(out, `bg-danger">HIGH`) {
		t.Error("expected HIGH severity badge with bg-danger class")
	}
	if !strings.Contains(out, `bg-warning text-dark">MEDIUM`) {
		t.Error("expected MEDIUM severity badge with bg-warning class")
	}
	if !strings.Contains(out, `bg-secondary">LOW`) {
		t.Error("expected LOW severity badge with bg-secondary class")
	}
}

func TestRenderHTML_ProjectRows(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	for _, path := range []string{"group/proj-a", "group/proj-b", "group/proj-c"} {
		if !strings.Contains(out, path) {
			t.Errorf("expected output to contain project %q", path)
		}
	}
}

func TestRenderHTML_FindingRows(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	for _, want := range []string{
		"INCLUDE_REMOTE",
		"VARIABLE_INJECTION",
		"ARTIFACTS_NO_EXPIRE",
		"Remote include",
		"Variable injection",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain finding %q", want)
		}
	}
}

func TestRenderHTML_EmptyReport(t *testing.T) {
	rep := Build(nil, Options{})
	out := renderHTML(t, rep)
	if !strings.Contains(out, "GoGatoZ Security Report") {
		t.Error("expected report header even with no data")
	}
	if !strings.Contains(out, `"chartSeverity"`) {
		t.Error("expected chart canvas even with no data")
	}
}

func TestRenderHTML_OnlyFindings(t *testing.T) {
	out := renderHTML(t, buildTestReport(true))
	// proj-c has no findings and should be excluded
	if strings.Contains(out, "group/proj-c") {
		t.Error("expected proj-c to be excluded with OnlyFindings=true")
	}
	// proj-a and proj-b should still be present
	if !strings.Contains(out, "group/proj-a") {
		t.Error("expected proj-a to be included")
	}
}

func TestRenderHTML_Version(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	if !strings.Contains(out, "v0.0.0-test") {
		t.Error("expected version string in footer")
	}
}

func TestRenderHTML_ExploitableSection(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	for _, want := range []string{
		`id="exploitableTable"`,
		"Exploitable Projects",
		"$('#exploitableTable').DataTable(",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q", want)
		}
	}
}

func TestRenderHTML_ExploitableSectionHidden(t *testing.T) {
	rep := Build(nil, Options{})
	out := renderHTML(t, rep)
	if strings.Contains(out, `id="exploitableTable"`) {
		t.Error("expected exploitable table element to be hidden when no exploitable findings")
	}
	if strings.Contains(out, "Exploitable Projects") {
		t.Error("expected exploitable section header to be hidden when no exploitable findings")
	}
}

func TestRenderHTML_ExploitableCommand(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	// proj-d has SELF_HOSTED_EXPOSED with RunnerTagHits docker,shell_exec
	if !strings.Contains(out, "gogatoz attack -t group/proj-d --commit-ci --payload ror-shell --tags docker,shell_exec") {
		t.Error("expected ror-shell command for SELF_HOSTED_EXPOSED in proj-d")
	}
	// proj-d also has PLAINTEXT_SECRET
	if !strings.Contains(out, "gogatoz attack -t group/proj-d --secrets --project-vars --output-json") {
		t.Error("expected secrets command for PLAINTEXT_SECRET in proj-d")
	}
}

func TestRenderHTML_ExploitableSummaryCard(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	if !strings.Contains(out, "Exploitable") {
		t.Error("expected Exploitable summary card")
	}
}

func TestRenderHTML_ExploitableCopyButton(t *testing.T) {
	out := renderHTML(t, buildTestReport(false))
	if !strings.Contains(out, "copy-btn") {
		t.Error("expected copy-btn class in exploitable table")
	}
	if !strings.Contains(out, "data-cmd=") {
		t.Error("expected data-cmd attribute on copy buttons")
	}
}

func TestComputeTypeCounts(t *testing.T) {
	rep := buildTestReport(false)
	counts := computeTypeCounts(rep)
	// proj-a: INCLUDE_REMOTE, VARIABLE_INJECTION; proj-b: ARTIFACTS_NO_EXPIRE; proj-d: SELF_HOSTED_EXPOSED, PLAINTEXT_SECRET
	if len(counts) != 5 {
		t.Fatalf("expected 5 finding types, got %d", len(counts))
	}
	for _, tc := range counts {
		if tc.Count != 1 {
			t.Errorf("expected count=1 for %s, got %d", tc.ID, tc.Count)
		}
	}
}

func TestFlattenFindings(t *testing.T) {
	rep := buildTestReport(false)
	flat := flattenFindings(rep)
	// proj-a: 2, proj-b: 1, proj-d: 2 = 5 total
	if len(flat) != 5 {
		t.Fatalf("expected 5 flat findings, got %d", len(flat))
	}
	// Verify project association
	found := false
	for _, f := range flat {
		if f.ID == "VARIABLE_INJECTION" && f.Project == "group/proj-a" && f.JobName == "deploy" {
			found = true
		}
	}
	if !found {
		t.Error("expected VARIABLE_INJECTION finding associated with group/proj-a job=deploy")
	}
}
