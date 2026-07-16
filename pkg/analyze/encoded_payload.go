package analyze

import (
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

var (
	longBase64Re = regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,3}`)

	base64DecodeExecRe = regexp.MustCompile(`(?i)(base64\s+-d|base64\s+--decode)\s*.*\|\s*(ba)?sh`)

	hexBlobRe = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){10,}`)

	xxdDecodeRe = regexp.MustCompile(`(?i)xxd\s+-r.*\|\s*(ba)?sh`)

	binaryMagicBase64 = []struct {
		prefix string
		name   string
	}{
		{"f0VMRg", "ELF binary"},
		{"TVqQ", "PE executable"},
		{"TVpB", "PE executable (alt)"},
		{"TVpR", "PE executable (alt2)"},
		{"yv66vg", "Java class"},
		{"UEsD", "ZIP/JAR archive"},
		{"UEsF", "ZIP archive (alt)"},
		{"H4sI", "gzip archive"},
		{"AAAA", "possible binary header"},
	}

	echoHexExecRe = regexp.MustCompile(`(?i)echo\s+-[en]+\s+.*\\x[0-9a-fA-F].*\|\s*(ba)?sh`)

	chmodExecRe = regexp.MustCompile(`(?i)chmod\s+\+x\s+\S+\s*[;&|]+\s*\./`)
)

//nolint:gocognit // complexity from distinct pattern branches, each is a simple check
func detectEncodedPayloads(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		lines := effectiveScripts(job, doc)
		found := false
		for _, line := range lines {
			if found {
				break
			}
			trimmed := strings.TrimSpace(line)

			if base64DecodeExecRe.MatchString(trimmed) {
				findings = append(findings, Finding{
					ID:          ScriptEncodedPayloadID,
					Severity:    SeverityHigh,
					Title:       "Base64-decoded content piped to shell",
					Description: "CI script decodes base64 content and pipes it to a shell for execution. This is a common technique for smuggling malicious payloads through CI pipelines.",
					Evidence:    stringutil.TruncateEvidence("line="+trimmed, 200),
					JobName:     job.Name,
				})
				found = true
				break
			}

			if xxdDecodeRe.MatchString(trimmed) {
				findings = append(findings, Finding{
					ID:          ScriptEncodedPayloadID,
					Severity:    SeverityHigh,
					Title:       "Hex-decoded content piped to shell",
					Description: "CI script uses xxd to decode hex content and pipe it to a shell. This obfuscates the true payload from code review.",
					Evidence:    stringutil.TruncateEvidence("line="+trimmed, 200),
					JobName:     job.Name,
				})
				found = true
				break
			}

			if echoHexExecRe.MatchString(trimmed) {
				findings = append(findings, Finding{
					ID:          ScriptEncodedPayloadID,
					Severity:    SeverityHigh,
					Title:       "Hex-escaped echo piped to shell",
					Description: "CI script uses echo with hex escape sequences piped to a shell. This technique hides executable content from human review.",
					Evidence:    stringutil.TruncateEvidence("line="+trimmed, 200),
					JobName:     job.Name,
				})
				found = true
				break
			}

			if longBase64Re.MatchString(trimmed) {
				match := longBase64Re.FindString(trimmed)
				for _, magic := range binaryMagicBase64 {
					if strings.HasPrefix(match, magic.prefix) {
						findings = append(findings, Finding{
							ID:          ScriptEncodedPayloadID,
							Severity:    SeverityHigh,
							Title:       "Binary payload embedded as base64 (" + magic.name + ")",
							Description: "CI script contains a base64-encoded " + magic.name + ". Native binaries smuggled in CI scripts are a supply chain attack vector (Jscrambler campaign).",
							Evidence:    stringutil.TruncateEvidence("magic="+magic.prefix+" line="+trimmed, 200),
							JobName:     job.Name,
						})
						found = true
						break
					}
				}
			}

			if !found && hexBlobRe.MatchString(trimmed) {
				findings = append(findings, Finding{
					ID:          ScriptEncodedPayloadID,
					Severity:    SeverityHigh,
					Title:       "Large hex-encoded blob in CI script",
					Description: "CI script contains a large sequence of hex-escaped bytes (10+). This may encode a binary payload or obfuscated command.",
					Evidence:    stringutil.TruncateEvidence("line="+trimmed, 200),
					JobName:     job.Name,
				})
				found = true
			}

			if !found && chmodExecRe.MatchString(trimmed) {
				findings = append(findings, Finding{
					ID:          ScriptEncodedPayloadID,
					Severity:    SeverityHigh,
					Title:       "Script makes file executable and runs it inline",
					Description: "CI script sets execute permission and immediately runs a file. Combined with encoded content, this is a binary drop-and-execute pattern.",
					Evidence:    stringutil.TruncateEvidence("line="+trimmed, 200),
					JobName:     job.Name,
				})
				found = true
			}
		}
	}
	return findings
}
