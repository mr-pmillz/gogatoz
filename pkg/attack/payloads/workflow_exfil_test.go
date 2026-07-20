package payloads

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestGenerateWorkflowExfilYAML_Default(t *testing.T) {
	yaml := GenerateWorkflowExfilYAML(WorkflowExfilOptions{})
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v\nYAML:\n%s", err, yaml)
	}
	if len(doc.Jobs) == 0 {
		t.Fatal("expected at least one job")
	}
	if doc.Jobs[0].Name != "code-format" {
		t.Errorf("expected job name 'code-format', got %q", doc.Jobs[0].Name)
	}
	if !strings.Contains(yaml, "printenv") {
		t.Error("expected printenv in script")
	}
	if !strings.Contains(yaml, "expire_in: 1 day") {
		t.Error("expected 1 day expiry")
	}
}

func TestGenerateWorkflowExfilYAML_CustomDisguise(t *testing.T) {
	yaml := GenerateWorkflowExfilYAML(WorkflowExfilOptions{
		DisguiseName: "dependency-check",
	})
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if doc.Jobs[0].Name != "dependency-check" {
		t.Errorf("expected job name 'dependency-check', got %q", doc.Jobs[0].Name)
	}
	if !strings.Contains(yaml, "dep-report.json") {
		t.Error("expected dep-report.json output file for dep-themed disguise")
	}
}

func TestGenerateWorkflowExfilYAML_WithWebhook(t *testing.T) {
	yaml := GenerateWorkflowExfilYAML(WorkflowExfilOptions{
		WebhookURL: "https://callback.example.com/recv",
	})
	if !strings.Contains(yaml, "callback.example.com") {
		t.Error("expected webhook URL in output")
	}
	_, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v\nYAML:\n%s", err, yaml)
	}
}

func TestGenerateWorkflowExfilYAML_WithTags(t *testing.T) {
	yaml := GenerateWorkflowExfilYAML(WorkflowExfilOptions{
		Common: CommonOptions{
			Tags:  []string{"shell_executor"},
			Image: "alpine:latest",
		},
	})
	if !strings.Contains(yaml, "shell_executor") {
		t.Error("expected runner tag in output")
	}
	if !strings.Contains(yaml, "alpine:latest") {
		t.Error("expected image in output")
	}
	_, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
}

func TestGenerateWorkflowExfilYAML_WithGroupVars(t *testing.T) {
	yaml := GenerateWorkflowExfilYAML(WorkflowExfilOptions{
		DumpGroupVars: true,
	})
	if !strings.Contains(yaml, "groups/") {
		t.Error("expected group variable dump in output")
	}
	_, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
}
