package analyze

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

var (
	fromCharCodeRe = regexp.MustCompile(`(?i)String\.fromCharCode\s*\([\d,\s]{20,}\)`)
	pythonChrRe    = regexp.MustCompile(`(?i)(chr\(\d+\)\s*\+\s*){5,}`)
	pythonBytesRe  = regexp.MustCompile(`(?i)bytes\(\s*\[\s*(\d+\s*,\s*){5,}`)
	rubyPackRe     = regexp.MustCompile(`(?i)\[\s*(\d+\s*,\s*){5,}.*\]\.pack\s*\(\s*"C\*"\s*\)`)
	perlPackRe     = regexp.MustCompile(`(?i)pack\s*\(\s*"C\*"\s*,\s*(\d+\s*,\s*){5,}`)
	printfHexRe    = regexp.MustCompile(`(?i)printf\s+['"]((\\x[0-9a-fA-F]{2}){10,})`)
)

func detectScriptObfuscation(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		var foundUnicode, foundWhitespace, foundCharcode bool
		for _, line := range effectiveScripts(job, doc) {
			if !foundUnicode {
				if reason := checkObfuscation(line); reason != "" {
					findings = append(findings, Finding{
						ID:          "SCRIPT_OBFUSCATION",
						Severity:    SeverityHigh,
						Title:       "Script contains obfuscated or invisible characters",
						Description: "CI/CD script contains suspicious Unicode characters (" + reason + ") that can hide malicious code from human reviewers. This technique has been used in real supply chain attacks (Trojan Source, CVE-2021-42574).",
						Evidence:    stringutil.TruncateEvidence("line="+line, 200),
						JobName:     job.Name,
					})
					foundUnicode = true
				}
			}

			if !foundWhitespace {
				if reason := checkWhitespaceHiding(line); reason != "" {
					findings = append(findings, Finding{
						ID:          WhitespaceHidingID,
						Severity:    SeverityMedium,
						Title:       "Script hides code with excessive whitespace",
						Description: "CI/CD script line " + reason + ". This technique was used in the AsyncAPI supply chain attack to push obfuscated code off-screen in diff views.",
						Evidence:    stringutil.TruncateEvidence("line="+line, 200),
						JobName:     job.Name,
					})
					foundWhitespace = true
				}
			}

			if !foundCharcode {
				if reason := checkCharCodeObfuscation(line); reason != "" {
					findings = append(findings, Finding{
						ID:          CharcodeObfuscationID,
						Severity:    SeverityMedium,
						Title:       "Character-code obfuscation in CI script",
						Description: "CI/CD script constructs strings from character codes (" + reason + "). This technique hides C2 hostnames and URLs from static analysis, as seen in the Injective SDK attack.",
						Evidence:    stringutil.TruncateEvidence("line="+line, 200),
						JobName:     job.Name,
					})
					foundCharcode = true
				}
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

func checkWhitespaceHiding(line string) string {
	if len(line) == 0 {
		return ""
	}
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return ""
	}
	leadingSpaces := utf8.RuneCountInString(line) - utf8.RuneCountInString(trimmed)
	if leadingSpaces >= 40 {
		return "has 40+ leading spaces pushing content off-screen"
	}
	if utf8.RuneCountInString(line) > 500 {
		contentStart := strings.IndexFunc(line, func(r rune) bool { return r != ' ' && r != '\t' })
		if contentStart > len(line)/2 {
			return "is abnormally long with content clustered at the end"
		}
	}
	return ""
}

func checkCharCodeObfuscation(line string) string {
	if fromCharCodeRe.MatchString(line) {
		return "String.fromCharCode"
	}
	if pythonChrRe.MatchString(line) {
		return "Python chr() concatenation"
	}
	if pythonBytesRe.MatchString(line) {
		return "Python bytes() array"
	}
	if rubyPackRe.MatchString(line) {
		return "Ruby Array.pack"
	}
	if perlPackRe.MatchString(line) {
		return "Perl pack()"
	}
	if printfHexRe.MatchString(line) {
		return "printf hex escapes"
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
