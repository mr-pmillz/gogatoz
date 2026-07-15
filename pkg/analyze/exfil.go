package analyze

import (
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

var (
	envDumpCmds = []string{
		"printenv", "env >", "env |", "env>>", "set >", "set |",
		"export >", "export |", "compgen -v",
		"cat /proc/self/environ", "cat /proc/*/environ",
		"strings /proc/", "/proc/self/environ",
	}

	httpExfilPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)curl\s+.*-[dXF]\s`),
		regexp.MustCompile(`(?i)curl\s+.*--data`),
		regexp.MustCompile(`(?i)curl\s+.*--upload-file`),
		regexp.MustCompile(`(?i)wget\s+.*--post-(data|file)`),
		regexp.MustCompile(`(?i)wget\s+.*--method\s+PUT`),
	}

	secretVarRefs = []string{
		"$CI_JOB_TOKEN", "$PRIVATE_TOKEN", "$CI_BUILD_TOKEN",
		"$GITLAB_TOKEN", "$DEPLOY_TOKEN", "$CI_REGISTRY_PASSWORD",
		"${CI_JOB_TOKEN}", "${PRIVATE_TOKEN}", "${CI_BUILD_TOKEN}",
		"${GITLAB_TOKEN}", "${DEPLOY_TOKEN}", "${CI_REGISTRY_PASSWORD}",
	}

	envDumpToFileRe = regexp.MustCompile(`(?i)(printenv|env|set|export)\s*(\|[^>]*)?(\s*>>?\s*)(\S+)`)
)

func detectSecretExfiltration(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		findings = append(findings, analyzeJobExfil(job, effectiveScripts(job, doc))...)
	}
	return findings
}

type exfilSignals struct {
	envDump, httpExfil, secretInHTTP bool
	envDumpEvidence, httpEvidence, secretHTTPEvidence string
}

//nolint:gocognit // linear scan through pattern categories
func scanExfilSignals(lines []string) exfilSignals {
	var s exfilSignals
	for _, line := range lines {
		lower := strings.ToLower(line)
		trimmed := strings.TrimSpace(line)

		if !s.envDump {
			for _, cmd := range envDumpCmds {
				if strings.Contains(lower, strings.ToLower(cmd)) {
					s.envDump = true
					s.envDumpEvidence = trimmed
					break
				}
			}
		}
		if !s.httpExfil {
			for _, re := range httpExfilPatterns {
				if re.MatchString(trimmed) {
					s.httpExfil = true
					s.httpEvidence = trimmed
					break
				}
			}
		}
		if !s.secretInHTTP && containsHTTPCall(lower) {
			for _, sv := range secretVarRefs {
				if strings.Contains(line, sv) {
					s.secretInHTTP = true
					s.secretHTTPEvidence = trimmed
					break
				}
			}
		}
		if hasPipeToHTTP(lower) {
			s.httpExfil = true
			if s.httpEvidence == "" {
				s.httpEvidence = trimmed
			}
		}
	}
	return s
}

//nolint:gocognit // kept flat for readability; complexity comes from distinct finding branches
func analyzeJobExfil(job pipeline.Job, lines []string) []Finding {
	var findings []Finding
	s := scanExfilSignals(lines)

	if s.envDump && s.httpExfil {
		findings = append(findings, Finding{
			ID:       SecretExfilHTTPID,
			Severity: SeverityCritical,
			Title:    "Environment secrets exfiltrated via HTTP",
			Description: "This job dumps environment variables and sends data to an external endpoint via HTTP. " +
				"This is a hallmark of CI/CD secret exfiltration campaigns (Hades, GhostAction, Megalodon).",
			Evidence: truncateEvidence("dump="+s.envDumpEvidence+" exfil="+s.httpEvidence, 200),
			JobName:  job.Name,
		})
	} else if s.secretInHTTP {
		findings = append(findings, Finding{
			ID:       SecretExfilHTTPID,
			Severity: SeverityCritical,
			Title:    "Secret variable referenced in HTTP request",
			Description: "This job references a known secret variable (CI_JOB_TOKEN, PRIVATE_TOKEN, etc.) " +
				"in an HTTP request, indicating possible credential exfiltration.",
			Evidence: truncateEvidence("line="+s.secretHTTPEvidence, 200),
			JobName:  job.Name,
		})
	}

	if s.envDump {
		dumpFile := extractDumpFilename(lines)
		if dumpFile != "" && jobArtifactContains(job, dumpFile) {
			findings = append(findings, Finding{
				ID:       SecretExfilArtifactID,
				Severity: SeverityHigh,
				Title:    "Environment dump uploaded as CI artifact",
				Description: "This job dumps environment variables to a file and uploads it as a CI artifact. " +
					"Anyone with project read access can download the artifact and extract secrets.",
				Evidence: truncateEvidence("dump_file="+dumpFile+" dump="+s.envDumpEvidence, 200),
				JobName:  job.Name,
			})
		}
	}
	return findings
}

func containsHTTPCall(lower string) bool {
	return strings.Contains(lower, "curl") || strings.Contains(lower, "wget") ||
		strings.Contains(lower, "http.post") || strings.Contains(lower, "requests.post") ||
		strings.Contains(lower, "invoke-webrequest") || strings.Contains(lower, "invoke-restmethod")
}

func hasPipeToHTTP(lower string) bool {
	return (strings.Contains(lower, "printenv") || strings.Contains(lower, "env |") ||
		strings.Contains(lower, "cat /proc")) &&
		(strings.Contains(lower, "| curl") || strings.Contains(lower, "|curl") ||
			strings.Contains(lower, "| wget") || strings.Contains(lower, "|wget"))
}

func extractDumpFilename(lines []string) string {
	for _, line := range lines {
		if m := envDumpToFileRe.FindStringSubmatch(line); len(m) >= 5 {
			return strings.TrimSpace(m[4])
		}
	}
	return ""
}

func jobArtifactContains(job pipeline.Job, filename string) bool {
	if job.Artifacts == nil {
		return false
	}
	paths, ok := job.Artifacts["paths"]
	if !ok {
		return false
	}
	pathList, ok := paths.([]any)
	if !ok {
		return false
	}
	base := filepathBase(filename)
	for _, p := range pathList {
		ps, ok := p.(string)
		if !ok {
			continue
		}
		if ps == filename || ps == base || strings.Contains(ps, base) ||
			ps == "*" || ps == "./" || strings.HasSuffix(ps, "/*") {
			return true
		}
	}
	return false
}

func filepathBase(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
