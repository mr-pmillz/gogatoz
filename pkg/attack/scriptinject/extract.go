// Package scriptinject extracts and injects into external scripts
// referenced by GitLab CI pipeline configurations. This enables
// "workflow hopping" attacks where the CI YAML is unchanged but
// scripts it calls are modified to execute attacker payloads.
package scriptinject

import (
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// ScriptRef represents a reference to an external script found in a CI job.
type ScriptRef struct {
	Path    string // file path relative to repo root (e.g. "scripts/build.sh")
	JobName string // CI job that references this script
	Line    string // original script line containing the reference
}

// scriptFileExts lists extensions that indicate a script file path.
var scriptFileExts = []string{
	".sh", ".bash", ".py", ".rb", ".pl", ".js", ".ts", ".mjs",
}

// interpreterPatterns match lines like: bash scripts/build.sh, python3 tools/lint.py, etc.
// Group 1 captures the file path argument.
var interpreterPatterns = []*regexp.Regexp{
	// bash/sh/zsh/dash followed by a file path
	regexp.MustCompile(`(?:^|\s)(?:bash|sh|zsh|dash)\s+([\w./_-]+\.\w+)`),
	// python/python2/python3 followed by a file path
	regexp.MustCompile(`(?:^|\s)(?:python3?|python2)\s+([\w./_-]+\.py)\b`),
	// ruby followed by a file path
	regexp.MustCompile(`(?:^|\s)ruby\s+([\w./_-]+\.rb)\b`),
	// perl followed by a file path
	regexp.MustCompile(`(?:^|\s)perl\s+([\w./_-]+\.pl)\b`),
	// node/nodejs followed by a file path
	regexp.MustCompile(`(?:^|\s)(?:node|nodejs)\s+([\w./_-]+\.(?:js|ts|mjs))\b`),
	// source or . followed by a file path
	regexp.MustCompile(`(?:^|\s)(?:source|\.)\s+([\w./_-]+\.\w+)`),
}

// directExecPattern matches ./path/to/script or path/to/script.sh at start of line.
var directExecPattern = regexp.MustCompile(`(?:^|\s)(?:\./|)((?:[\w._-]+/)+[\w._-]+\.\w+)`)

// makePattern matches lines starting with make (implies Makefile).
var makePattern = regexp.MustCompile(`(?:^|\s)make\s+`)

// ExtractScriptRefs finds all external script file references in a parsed CI document.
// It returns deduplicated ScriptRef entries ordered by first occurrence.
func ExtractScriptRefs(doc *pipeline.Document) []ScriptRef {
	seen := make(map[string]bool)
	var refs []ScriptRef

	for _, job := range doc.Jobs {
		for _, line := range job.Script {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Try interpreter patterns first
			for _, pat := range interpreterPatterns {
				if m := pat.FindStringSubmatch(line); len(m) > 1 {
					path := cleanPath(m[1])
					if !seen[path] {
						seen[path] = true
						refs = append(refs, ScriptRef{Path: path, JobName: job.Name, Line: line})
					}
				}
			}
			// Try direct execution pattern (./scripts/build.sh or scripts/build.sh)
			if m := directExecPattern.FindStringSubmatch(line); len(m) > 1 {
				path := cleanPath(m[1])
				if hasScriptExt(path) && !seen[path] {
					seen[path] = true
					refs = append(refs, ScriptRef{Path: path, JobName: job.Name, Line: line})
				}
			}
			// make implies Makefile
			if makePattern.MatchString(line) && !seen["Makefile"] {
				seen["Makefile"] = true
				refs = append(refs, ScriptRef{Path: "Makefile", JobName: job.Name, Line: line})
			}
		}
	}
	return refs
}

func cleanPath(p string) string {
	p = strings.TrimPrefix(p, "./")
	return strings.TrimSpace(p)
}

func hasScriptExt(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range scriptFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
