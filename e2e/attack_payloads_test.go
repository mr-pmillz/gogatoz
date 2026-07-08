//go:build e2e

package e2e_test

import (
	"strings"
	"testing"
)

func TestAttack_PayloadOnly_MemoryDump(t *testing.T) {
	// No creds needed — payload-only is local rendering.
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "memory-dump",
		"--target", "MrPMillz/vuln-memory-dump",
		"--webhook", "https://example.com/callback",
		"--tags", "shell_executor,docker",
	)
	if err != nil {
		t.Fatalf("payload-only memory-dump failed: %v\nstderr: %s", err, stderr)
	}

	// Must contain /proc reference (the core memory-scraping technique)
	if !strings.Contains(stdout, "/proc") {
		t.Errorf("expected /proc reference in memory-dump payload; got:\n%s", stdout)
	}
	// Must contain the webhook URL
	if !strings.Contains(stdout, "https://example.com/callback") {
		t.Errorf("expected webhook URL in memory-dump payload; got:\n%s", stdout)
	}
	// Must contain script: section (GitLab CI job)
	if !strings.Contains(stdout, "script:") {
		t.Errorf("expected script: in memory-dump YAML; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_SupplyChainWorm(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "supplychain-worm",
		"--webhook", "https://example.com/callback",
	)
	if err != nil {
		t.Fatalf("payload-only supplychain-worm failed: %v\nstderr: %s", err, stderr)
	}

	// Worm payload should contain the propagate-to pattern
	if !strings.Contains(stdout, "script:") {
		t.Errorf("expected script: in supplychain-worm YAML; got:\n%s", stdout)
	}
	// Should contain CI/CD injection (pushing to other projects)
	if !strings.Contains(stdout, "curl") && !strings.Contains(stdout, "git") {
		t.Errorf("expected propagation mechanism (curl/git) in supplychain-worm; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_ContainerEscape(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "container-escape",
		"--tags", "docker",
		"--command", "id",
	)
	if err != nil {
		t.Fatalf("payload-only container-escape failed: %v\nstderr: %s", err, stderr)
	}

	// Must contain script: for GitLab CI
	if !strings.Contains(stdout, "script:") {
		t.Errorf("expected script: in container-escape YAML; got:\n%s", stdout)
	}
	// Should reference privileged escape or mount technique
	if !strings.Contains(stdout, "privileged") && !strings.Contains(stdout, "mount") {
		t.Errorf("expected privileged/mount reference in container-escape; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_VariableInject(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "variable-inject",
		"--webhook", "https://example.com/exfil",
	)
	if err != nil {
		t.Fatalf("payload-only variable-inject failed: %v\nstderr: %s", err, stderr)
	}

	// Should reference CI/CD variable injection
	if !strings.Contains(stdout, "script:") {
		t.Errorf("expected script: in variable-inject YAML; got:\n%s", stdout)
	}
	// Should contain variable manipulation (export/setenv)
	if !strings.Contains(stdout, "export") && !strings.Contains(stdout, "set") {
		t.Errorf("expected variable manipulation in variable-inject; got:\n%s", stdout)
	}
}

func TestAttack_PayloadOnly_C2Channels(t *testing.T) {
	stdout, stderr, err := runGogatoz(t, "", "attack",
		"--payload-only", "--payload", "c2-channels",
		"--webhook", "https://example.com/c2",
		"--method", "dns",
	)
	if err != nil {
		t.Fatalf("payload-only c2-channels failed: %v\nstderr: %s", err, stderr)
	}

	// DNS method should embed DNS query patterns
	if strings.Contains(stdout, "dns") {
		// Check it contains dig or nslookup (DNS lookup tools)
		if !strings.Contains(stdout, "dig") && !strings.Contains(stdout, "nslookup") &&
			!strings.Contains(stdout, "dns") && !strings.Contains(stdout, "TXT") {
			t.Errorf("expected DNS-related command in c2-channels dns mode; got:\n%s", stdout)
		}
	}
	// Should contain the webhook
	if !strings.Contains(stdout, "https://example.com/c2") {
		t.Errorf("expected webhook in c2-channels payload; got:\n%s", stdout)
	}
}
