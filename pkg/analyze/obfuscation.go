package analyze

import (
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func detectScriptObfuscation(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		for _, line := range effectiveScripts(job, doc) {
			if reason := checkObfuscation(line); reason != "" {
				findings = append(findings, Finding{
					ID:          "SCRIPT_OBFUSCATION",
					Severity:    SeverityHigh,
					Title:       "Script contains obfuscated or invisible characters",
					Description: "CI/CD script contains suspicious Unicode characters (" + reason + ") that can hide malicious code from human reviewers. This technique has been used in real supply chain attacks (Trojan Source, CVE-2021-42574).",
					Evidence:    truncateEvidence("line="+line, 200),
					JobName:     job.Name,
				})
				break
			}
		}
	}
	return findings
}

func checkObfuscation(line string) string {
	for _, r := range line {
		if isZeroWidth(r) {
			return "zero-width character"
		}
		if isBidiOverride(r) {
			return "bidirectional override (Trojan Source)"
		}
	}
	return ""
}

func isZeroWidth(r rune) bool {
	switch r {
	case '\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\uFEFF', // byte order mark
		'\u00AD', // soft hyphen
		'\u2060', // word joiner
		'\u180E': // Mongolian vowel separator
		return true
	}
	if r >= '\uFE00' && r <= '\uFE0F' {
		return true
	}
	if r >= '\U000E0100' && r <= '\U000E01EF' {
		return true
	}
	return false
}

func isBidiOverride(r rune) bool {
	switch r {
	case '\u202A', // left-to-right embedding
		'\u202B', // right-to-left embedding
		'\u202C', // pop directional formatting
		'\u202D', // left-to-right override
		'\u202E', // right-to-left override
		'\u2066', // left-to-right isolate
		'\u2067', // right-to-left isolate
		'\u2068', // first strong isolate
		'\u2069': // pop directional isolate
		return true
	}
	return false
}

