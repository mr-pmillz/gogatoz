package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const testPipelineYAML = `
stages:
  - build
  - test
  - deploy
compile:
  stage: build
  script: echo compile
lint:
  stage: build
  script: echo lint
unit_test:
  stage: test
  script: echo test
  needs: [compile]
deploy_prod:
  stage: deploy
  script: echo deploy
  needs: [unit_test]
`

func runGraphCmd(t *testing.T, format, ciFile, outFile string, stdin *strings.Reader) (string, error) {
	t.Helper()

	parseGraphFormat = format
	parseGraphOutput = outFile

	cmd := &cobra.Command{Use: "test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if stdin != nil {
		cmd.SetIn(stdin)
	}

	var args []string
	if ciFile != "" {
		args = []string{ciFile}
	}

	err := runParseGraph(cmd, args)
	return buf.String(), err
}

func TestRunParseGraph_DOT(t *testing.T) {
	tmp := t.TempDir()
	ciFile := filepath.Join(tmp, ".gitlab-ci.yml")
	if err := os.WriteFile(ciFile, []byte(testPipelineYAML), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runGraphCmd(t, "dot", ciFile, "", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if !strings.Contains(out, "digraph pipeline {") {
		t.Error("DOT output missing digraph header")
	}
	if !strings.Contains(out, `"compile" -> "unit_test"`) {
		t.Error("DOT output missing compile -> unit_test edge")
	}
	if !strings.Contains(out, `"unit_test" -> "deploy_prod"`) {
		t.Error("DOT output missing unit_test -> deploy_prod edge")
	}
	if !strings.Contains(out, "cluster_build") {
		t.Error("DOT output missing build stage cluster")
	}
}

func TestRunParseGraph_Mermaid(t *testing.T) {
	tmp := t.TempDir()
	ciFile := filepath.Join(tmp, ".gitlab-ci.yml")
	if err := os.WriteFile(ciFile, []byte(testPipelineYAML), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runGraphCmd(t, "mermaid", ciFile, "", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if !strings.Contains(out, "flowchart LR") {
		t.Error("Mermaid output missing flowchart header")
	}
	if !strings.Contains(out, "compile --> unit_test") {
		t.Error("Mermaid output missing compile --> unit_test edge")
	}
	if !strings.Contains(out, "unit_test --> deploy_prod") {
		t.Error("Mermaid output missing unit_test --> deploy_prod edge")
	}
}

func TestRunParseGraph_OutputFile(t *testing.T) {
	tmp := t.TempDir()
	ciFile := filepath.Join(tmp, ".gitlab-ci.yml")
	outFile := filepath.Join(tmp, "graph.dot")
	if err := os.WriteFile(ciFile, []byte(testPipelineYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := runGraphCmd(t, "dot", ciFile, outFile, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), "digraph pipeline {") {
		t.Error("output file missing DOT content")
	}
}

func TestRunParseGraph_Stdin(t *testing.T) {
	out, err := runGraphCmd(t, "dot", "", "", strings.NewReader(testPipelineYAML))
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if !strings.Contains(out, "digraph pipeline {") {
		t.Error("stdin mode: missing DOT output")
	}
}

func TestRunParseGraph_InvalidFormat(t *testing.T) {
	tmp := t.TempDir()
	ciFile := filepath.Join(tmp, ".gitlab-ci.yml")
	if err := os.WriteFile(ciFile, []byte(testPipelineYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := runGraphCmd(t, "svg", ciFile, "", nil)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error = %q, want 'unknown format'", err.Error())
	}
}

func TestRunParseGraph_MissingFile(t *testing.T) {
	_, err := runGraphCmd(t, "dot", "/nonexistent/.gitlab-ci.yml", "", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
