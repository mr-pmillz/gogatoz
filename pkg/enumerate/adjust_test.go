package enumerate

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// ---------------------------------------------------------------------------
// Existing tests (updated to pass nil doc for legacy fallback behavior)
// ---------------------------------------------------------------------------

func TestAdjustFindingsForRunnerRisk_BumpsOnRiskyExecutors(t *testing.T) {
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "MR_TAGGED_RUNNER",
			Severity: analyze.SeverityLow,
			Title:    "t",
		}},
		RunnerRiskyExecutors: map[string]int{"shell": 2},
	}
	adjustFindingsForRunnerRisk(&r, nil)
	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Fatalf("expected severity MEDIUM after bump, got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_BumpsMediumToHigh(t *testing.T) {
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityMedium,
			Title:    "t",
		}},
		RunnerRiskyExecutors: map[string]int{"docker": 1},
	}
	adjustFindingsForRunnerRisk(&r, nil)
	if got := r.Findings[0].Severity; got != analyze.SeverityHigh {
		t.Fatalf("expected severity HIGH after bump, got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_NoBumpWithoutSignals(t *testing.T) {
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "MR_TAGGED_RUNNER",
			Severity: analyze.SeverityLow,
			Title:    "t",
		}},
		// No risky executors and no tag hits
	}
	adjustFindingsForRunnerRisk(&r, nil)
	if got := r.Findings[0].Severity; got != analyze.SeverityLow {
		t.Fatalf("expected severity to remain LOW without correlation signals, got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_BumpsOnTagHitsOnly(t *testing.T) {
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "PRIVILEGED_RUNNER_RISK",
			Severity: analyze.SeverityLow,
			Title:    "t",
		}},
		RunnerTagHits: map[string]int{"build": 1},
	}
	adjustFindingsForRunnerRisk(&r, nil)
	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Fatalf("expected severity MEDIUM after bump from tag hits, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// New tests: executorRiskClass
// ---------------------------------------------------------------------------

func TestExecutorRiskClass(t *testing.T) {
	tests := []struct {
		executor string
		want     int
	}{
		{"shell", 3},
		{"docker", 2},
		{"kubernetes", 1},
		{"docker+machine", 0},
		{"docker-autoscaler", 0},
		{"unknown", 1},
		{"", 1},
	}
	for _, tt := range tests {
		t.Run(tt.executor, func(t *testing.T) {
			got := executorRiskClass(tt.executor)
			if got != tt.want {
				t.Errorf("executorRiskClass(%q) = %d, want %d", tt.executor, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// New tests: bumpByRiskClass
// ---------------------------------------------------------------------------

func TestBumpByRiskClass(t *testing.T) {
	tests := []struct {
		name      string
		sev       analyze.Severity
		riskClass int
		want      analyze.Severity
	}{
		{"LOW_shell", analyze.SeverityLow, 3, analyze.SeverityCritical},
		{"MEDIUM_shell", analyze.SeverityMedium, 3, analyze.SeverityCritical},
		{"LOW_docker", analyze.SeverityLow, 2, analyze.SeverityMedium},
		{"MEDIUM_docker", analyze.SeverityMedium, 2, analyze.SeverityHigh},
		{"LOW_kubernetes", analyze.SeverityLow, 1, analyze.SeverityLow},
		{"HIGH_ephemeral", analyze.SeverityHigh, 0, analyze.SeverityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bumpByRiskClass(tt.sev, tt.riskClass)
			if got != tt.want {
				t.Errorf("bumpByRiskClass(%s, %d) = %s, want %s", tt.sev, tt.riskClass, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// New tests: adjustFindingsForRunnerRisk with doc + per-tag executor data
// ---------------------------------------------------------------------------

func TestAdjustFindingsForRunnerRisk_ShellBumpsToCritical(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "build", Tags: []string{"ci"}}}}
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityLow,
			Title:    "t",
			JobName:  "build",
		}},
		RunnerTagExecutors: map[string]map[string]int{
			"ci": {"shell": 2},
		},
	}
	adjustFindingsForRunnerRisk(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityCritical {
		t.Fatalf("expected severity CRITICAL (shell bump), got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_DockerBumpsOneLevel(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "build", Tags: []string{"ci"}}}}
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityLow,
			Title:    "t",
			JobName:  "build",
		}},
		RunnerTagExecutors: map[string]map[string]int{
			"ci": {"docker": 1},
		},
	}
	adjustFindingsForRunnerRisk(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Fatalf("expected severity MEDIUM (docker bump), got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_KubernetesNoBump(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "deploy", Tags: []string{"k8s"}}}}
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "MR_TAGGED_RUNNER",
			Severity: analyze.SeverityLow,
			Title:    "t",
			JobName:  "deploy",
		}},
		RunnerTagExecutors: map[string]map[string]int{
			"k8s": {"kubernetes": 3},
		},
	}
	adjustFindingsForRunnerRisk(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityLow {
		t.Fatalf("expected severity to remain LOW (kubernetes no bump), got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_MixedExecutorsTakesWorst(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "build", Tags: []string{"ci", "k8s"}}}}
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityLow,
			Title:    "t",
			JobName:  "build",
		}},
		RunnerTagExecutors: map[string]map[string]int{
			"ci":  {"shell": 1},
			"k8s": {"kubernetes": 2},
		},
	}
	adjustFindingsForRunnerRisk(&r, doc)
	if got := r.Findings[0].Severity; got != analyze.SeverityCritical {
		t.Fatalf("expected severity CRITICAL (shell worst of mixed), got %s", got)
	}
}

func TestAdjustFindingsForRunnerRisk_FallbackLegacyBump(t *testing.T) {
	r := Result{
		Findings: []analyze.Finding{{
			ID:       "SELF_HOSTED_EXPOSED",
			Severity: analyze.SeverityLow,
			Title:    "t",
		}},
		RunnerRiskyExecutors: map[string]int{"shell": 1},
	}
	// nil doc — no per-tag data, falls back to legacy one-level bump
	adjustFindingsForRunnerRisk(&r, nil)
	if got := r.Findings[0].Severity; got != analyze.SeverityMedium {
		t.Fatalf("expected severity MEDIUM (legacy fallback bump), got %s", got)
	}
}

// ---------------------------------------------------------------------------
// New tests: addExecutorFindings
// ---------------------------------------------------------------------------

func TestAddExecutorFindings_ShellHighFinding(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "build", Tags: []string{"ci"}}}}
	r := Result{
		RunnerTagExecutors: map[string]map[string]int{
			"ci": {"shell": 2},
		},
	}
	addExecutorFindings(&r, doc)
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	f := r.Findings[0]
	if f.ID != "RUNNER_EXECUTOR_RISK" {
		t.Errorf("expected ID RUNNER_EXECUTOR_RISK, got %s", f.ID)
	}
	if f.Severity != analyze.SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %s", f.Severity)
	}
	if f.Title != "Job targets runners with shell executor" {
		t.Errorf("unexpected title: %s", f.Title)
	}
	if f.JobName != "build" {
		t.Errorf("expected job name build, got %s", f.JobName)
	}
}

func TestAddExecutorFindings_DockerMediumFinding(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "test", Tags: []string{"dind"}}}}
	r := Result{
		RunnerTagExecutors: map[string]map[string]int{
			"dind": {"docker": 3},
		},
	}
	addExecutorFindings(&r, doc)
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	f := r.Findings[0]
	if f.ID != "RUNNER_EXECUTOR_RISK" {
		t.Errorf("expected ID RUNNER_EXECUTOR_RISK, got %s", f.ID)
	}
	if f.Severity != analyze.SeverityMedium {
		t.Errorf("expected severity MEDIUM, got %s", f.Severity)
	}
	if f.Title != "Job targets runners with docker executor" {
		t.Errorf("unexpected title: %s", f.Title)
	}
}

func TestAddExecutorFindings_KubernetesNoFinding(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "deploy", Tags: []string{"k8s"}}}}
	r := Result{
		RunnerTagExecutors: map[string]map[string]int{
			"k8s": {"kubernetes": 5},
		},
	}
	addExecutorFindings(&r, doc)
	if len(r.Findings) != 0 {
		t.Fatalf("expected 0 findings for kubernetes-only, got %d", len(r.Findings))
	}
}

func TestAddExecutorFindings_NoRunnerDataNoFindings(t *testing.T) {
	doc := &pipeline.Document{Jobs: []pipeline.Job{{Name: "build", Tags: []string{"ci"}}}}
	r := Result{
		// Empty RunnerTagExecutors
		RunnerTagExecutors: map[string]map[string]int{},
	}
	addExecutorFindings(&r, doc)
	if len(r.Findings) != 0 {
		t.Fatalf("expected 0 findings without runner data, got %d", len(r.Findings))
	}
}
