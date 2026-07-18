package enumerate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumerateLocal_SingleFile(t *testing.T) {
	dir := t.TempDir()
	ciYAML := `stages: [build]
build:
  stage: build
  tags: [shell_executor]
  script:
    - echo "building"
    - printenv > env.txt
  artifacts:
    paths: [env.txt]
    when: always
`
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(ciYAML), 0644); err != nil {
		t.Fatal(err)
	}
	results, err := EnumerateLocal(context.Background(), []string{dir}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].HasCIPipeline {
		t.Error("expected HasCIPipeline=true")
	}
}

func TestEnumerateLocal_NoCI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	results, err := EnumerateLocal(context.Background(), []string{dir}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Error("expected 0 results for dir without .gitlab-ci.yml")
	}
}

func TestEnumerateLocal_DirectFile(t *testing.T) {
	dir := t.TempDir()
	ciFile := filepath.Join(dir, "custom-ci.yml")
	ciYAML := `stages: [test]
test:
  stage: test
  script: ["echo test"]
`
	if err := os.WriteFile(ciFile, []byte(ciYAML), 0644); err != nil {
		t.Fatal(err)
	}
	results, err := EnumerateLocal(context.Background(), []string{ciFile}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestEnumerateLocal_NestedDirs(t *testing.T) {
	root := t.TempDir()
	sub1 := filepath.Join(root, "proj-a")
	sub2 := filepath.Join(root, "proj-b")
	if err := os.MkdirAll(sub1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub2, 0755); err != nil {
		t.Fatal(err)
	}
	ci := "stages: [build]\nbuild:\n  stage: build\n  script: [\"echo hi\"]\n"
	if err := os.WriteFile(filepath.Join(sub1, ".gitlab-ci.yml"), []byte(ci), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub2, ".gitlab-ci.yml"), []byte(ci), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := EnumerateLocal(context.Background(), []string{root}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results from nested dirs, got %d", len(results))
	}
}

func TestEnumerateLocal_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	ci := "stages: [build]\nbuild:\n  stage: build\n  script: [\"echo hi\"]\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(ci), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := EnumerateLocal(ctx, []string{dir}, Options{})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestEnumerateLocal_InvalidPath(t *testing.T) {
	_, err := EnumerateLocal(context.Background(), []string{"/nonexistent/path"}, Options{})
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestEnumerateLocal_ParseError(t *testing.T) {
	dir := t.TempDir()
	// Invalid YAML that will fail parsing
	badYAML := ":\n  :\n    - [invalid: {yaml"
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}
	results, err := EnumerateLocal(context.Background(), []string{dir}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for parse error, got %d", len(results))
	}
	if results[0].Error == "" {
		t.Error("expected non-empty Error field for parse failure")
	}
}
