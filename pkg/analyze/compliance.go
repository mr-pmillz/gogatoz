package analyze

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Finding ID constants for compliance detections.
const (
	DebugTraceEnabledID     = "DEBUG_TRACE_ENABLED"
	UnverifiedScriptExecID  = "UNVERIFIED_SCRIPT_EXEC"
	UnpinnedPackageInstallID = "UNPINNED_PACKAGE_INSTALL"
)

// debugTraceVars are the CI variables that expose secrets when enabled.
var debugTraceVars = []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"}

// isTruthy returns true if a variable value is a truthy string
// (case-insensitive, trimmed).
func isTruthy(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

// detectDebugTrace checks for CI_DEBUG_TRACE or CI_DEBUG_SERVICES set to
// truthy values at the global or job level. When enabled, GitLab Runner
// prints every environment variable -- including masked secrets -- to job logs.
// When controls is non-nil and DebugTraceVariables is non-empty, those variable
// names replace the default debugTraceVars list.
func detectDebugTrace(doc *pipeline.Document, controls *config.ControlsConfig) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	vars := debugTraceVars
	if controls != nil && len(controls.DebugTraceVariables) > 0 {
		vars = controls.DebugTraceVariables
	}

	// Check global variables
	for _, varName := range vars {
		if val, ok := doc.Variables[varName]; ok {
			strVal := fmt.Sprintf("%v", val)
			if isTruthy(strVal) {
				findings = append(findings, Finding{
					ID:          DebugTraceEnabledID,
					Severity:    SeverityCritical,
					Title:       "CI debug trace enabled — secrets exposed in job logs",
					Description: "CI_DEBUG_TRACE or CI_DEBUG_SERVICES is enabled, which causes GitLab Runner to print every environment variable — including masked secrets — to the job log. This is a critical secret exposure risk.",
					Evidence:    fmt.Sprintf("%s=%s (global)", varName, strVal),
				})
			}
		}
	}

	// Check per-job variables
	for _, job := range doc.Jobs {
		for _, varName := range vars {
			if val, ok := job.Variables[varName]; ok {
				strVal := fmt.Sprintf("%v", val)
				if isTruthy(strVal) {
					findings = append(findings, Finding{
						ID:          DebugTraceEnabledID,
						Severity:    SeverityCritical,
						Title:       "CI debug trace enabled — secrets exposed in job logs",
						Description: "CI_DEBUG_TRACE or CI_DEBUG_SERVICES is enabled, which causes GitLab Runner to print every environment variable — including masked secrets — to the job log. This is a critical secret exposure risk.",
						Evidence:    fmt.Sprintf("%s=%s (job=%s)", varName, strVal, job.Name),
						JobName:     job.Name,
					})
				}
			}
		}
	}

	return findings
}

// verificationCommands are substrings that, if present on the same line,
// indicate the download/decode is followed by integrity verification.
var verificationCommands = []string{
	"sha256sum", "shasum", "gpg --verify", "cosign verify",
}

// hasVerification returns true if the line contains a verification command.
func hasVerification(line string) bool {
	lower := strings.ToLower(line)
	for _, cmd := range verificationCommands {
		if strings.Contains(lower, cmd) {
			return true
		}
	}
	return false
}

// Compiled regex patterns for unverified script execution.
var (
	// base64 decode piped to shell: base64 -d | bash, base64 --decode payload | sh
	reBase64Pipe = regexp.MustCompile(`(?i)base64\s+(-d|--decode)\b.*\|\s*(bash|sh|zsh)\b`)

	// Download to file then execute: curl -o file ... && bash file
	// or curl -o file ... && ./file
	reCurlThenExec = regexp.MustCompile(`(?i)curl\b.*-[oO]\s+(\S+).*[;&]+\s*(bash|sh|chmod\s+\+x|\./)`)

	// wget -O file then execute: wget -O file ... && bash file
	reWgetThenExec = regexp.MustCompile(`(?i)wget\b.*-O\s+(\S+).*[;&]+\s*(bash|sh|chmod\s+\+x|\./)`)

	// Redirect then exec: curl ... > file; bash file or curl ... > file; chmod +x file; ./file
	reCurlRedirectExec = regexp.MustCompile(`(?i)curl\b.*>\s*(\S+)\s*[;&]+\s*(bash|sh|chmod\s+\+x|\./)`)

	// wget redirect then exec
	reWgetRedirectExec = regexp.MustCompile(`(?i)wget\b.*>\s*(\S+)\s*[;&]+\s*(bash|sh|chmod\s+\+x|\./)`)

	// Python urllib download-exec pattern
	rePythonDownloadExec = regexp.MustCompile(`(?i)python[23]?\s+-(c|m)\s+.*urllib.*\|\s*(bash|sh)`)
)

// unverifiedScriptPattern pairs a regex with a human-readable description.
type unverifiedScriptPattern struct {
	re   *regexp.Regexp
	desc string
}

var unverifiedPatterns = []unverifiedScriptPattern{
	{reBase64Pipe, "Base64-encoded payload decoded and executed via shell"},
	{reCurlThenExec, "Downloaded script executed without integrity verification"},
	{reWgetThenExec, "Downloaded script executed without integrity verification"},
	{reCurlRedirectExec, "Downloaded script executed without integrity verification"},
	{reWgetRedirectExec, "Downloaded script executed without integrity verification"},
	{rePythonDownloadExec, "Python download-exec pattern pipes remote content to shell"},
}

// detectUnverifiedScriptExec detects broader unverified script execution
// patterns beyond what isRiskyRemoteScript() already catches. This includes
// base64-decode-to-shell, download-then-execute, and redirect-then-execute.
func detectUnverifiedScriptExec(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		for _, line := range effectiveScripts(job, doc) {
			if hasVerification(line) {
				continue
			}
			for _, pat := range unverifiedPatterns {
				if pat.re.MatchString(line) {
					findings = append(findings, Finding{
						ID:          UnverifiedScriptExecID,
						Severity:    SeverityHigh,
						Title:       "Unverified script execution detected",
						Description: pat.desc,
						Evidence:    truncateEvidence(line, 200),
						JobName:     job.Name,
					})
					break // one finding per line is sufficient
				}
			}
		}
	}

	return findings
}

// Compiled regex patterns for unpinned package installs.
// Note: Go's regexp uses RE2 which does not support lookaheads.
// Version pin checks are handled in the extraCheck functions.
var (
	// pip install <pkg> — version pin check done in extraCheck
	rePipUnpinned = regexp.MustCompile(`(?i)\bpip3?\s+install\s+`)

	// npm install/i <pkg> — version pin and npm ci checks done in extraCheck
	reNpmUnpinned = regexp.MustCompile(`(?i)\bnpm\s+(install|i)\s+`)

	// gem install <pkg> — version flag check done in extraCheck
	reGemUnpinned = regexp.MustCompile(`(?i)\bgem\s+install\s+`)

	// go install <pkg> — @version check done in extraCheck
	reGoUnpinned = regexp.MustCompile(`(?i)\bgo\s+install\s+`)

	// apk add <pkg> — =version check done in extraCheck
	reApkUnpinned = regexp.MustCompile(`(?i)\bapk\s+add\b`)

	// apt-get install <pkg> — =version check done in extraCheck
	reAptUnpinned = regexp.MustCompile(`(?i)\bapt(-get)?\s+install\b`)
)

// packageSkipIndicators are substrings that indicate the install is
// using a lockfile or constraint mechanism, making it safe.
var packageSkipIndicators = []string{
	"--requirement", "-r requirements", "--constraint",
	"package-lock.json", "Gemfile.lock",
}

// unpinnedPackagePattern pairs a regex with an additional check function.
type unpinnedPackagePattern struct {
	re         *regexp.Regexp
	name       string
	extraCheck func(line string) bool
}

var unpinnedPatterns = []unpinnedPackagePattern{
	{
		re:   rePipUnpinned,
		name: "pip",
		extraCheck: func(line string) bool {
			lower := strings.ToLower(line)
			// Skip if using requirements file or constraint
			if strings.Contains(lower, " -r ") || strings.Contains(lower, "--requirement") || strings.Contains(lower, "--constraint") {
				return false
			}
			// Find the package tokens after "pip install" / "pip3 install"
			idx := strings.Index(lower, "install")
			if idx < 0 {
				return false
			}
			rest := strings.TrimSpace(lower[idx+len("install"):])
			for _, tok := range strings.Fields(rest) {
				if strings.HasPrefix(tok, "-") {
					continue // skip flags
				}
				// If any package token has ==, it's pinned
				if strings.Contains(tok, "==") {
					continue
				}
				return true // found an unpinned package
			}
			return false
		},
	},
	{
		re:   reNpmUnpinned,
		name: "npm",
		extraCheck: func(line string) bool {
			lower := strings.ToLower(line)
			tokens := strings.Fields(lower)
			// Check for npm ci (uses lockfile, safe)
			for i, tok := range tokens {
				if tok == "npm" && i+1 < len(tokens) && tokens[i+1] == "ci" {
					return false
				}
			}
			// Find "install" or "i" after npm
			var installIdx int
			found := false
			for i, tok := range tokens {
				if tok == "npm" && i+1 < len(tokens) {
					next := tokens[i+1]
					if next == "install" || next == "i" {
						installIdx = i + 2
						found = true
						break
					}
				}
			}
			if !found || installIdx >= len(tokens) {
				return false
			}
			// Check package tokens after install
			for _, tok := range tokens[installIdx:] {
				if strings.HasPrefix(tok, "-") {
					continue // skip flags
				}
				// Packages with @version are pinned
				if strings.Contains(tok, "@") {
					// Check for scoped packages like @scope/pkg (not a version pin)
					if strings.HasPrefix(tok, "@") && !strings.Contains(tok[1:], "@") {
						return true // scoped package without version
					}
					continue // has @version, pinned
				}
				return true // found unpinned package
			}
			return false
		},
	},
	{
		re:   reGemUnpinned,
		name: "gem",
		extraCheck: func(line string) bool {
			lower := strings.ToLower(line)
			return !strings.Contains(lower, "--version") && !strings.Contains(lower, " -v ")
		},
	},
	{
		re:   reGoUnpinned,
		name: "go install",
		extraCheck: func(line string) bool {
			lower := strings.ToLower(line)
			idx := strings.Index(lower, "go install")
			if idx < 0 {
				return false
			}
			rest := strings.TrimSpace(lower[idx+len("go install"):])
			pkg := strings.Fields(rest)
			if len(pkg) == 0 {
				return false
			}
			return !strings.Contains(pkg[0], "@")
		},
	},
	{
		re:   reApkUnpinned,
		name: "apk",
		extraCheck: func(line string) bool {
			lower := strings.ToLower(line)
			idx := strings.Index(lower, "apk add")
			if idx < 0 {
				return false
			}
			rest := lower[idx+len("apk add"):]
			for _, tok := range strings.Fields(rest) {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				// If first package token has =, it's pinned
				return !strings.Contains(tok, "=")
			}
			return false
		},
	},
	{
		re:   reAptUnpinned,
		name: "apt-get",
		extraCheck: func(line string) bool {
			lower := strings.ToLower(line)
			var idx int
			if i := strings.Index(lower, "apt-get install"); i >= 0 {
				idx = i + len("apt-get install")
			} else if i := strings.Index(lower, "apt install"); i >= 0 {
				idx = i + len("apt install")
			} else {
				return false
			}
			rest := lower[idx:]
			for _, tok := range strings.Fields(rest) {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				return !strings.Contains(tok, "=")
			}
			return false
		},
	},
}

// detectUnpinnedPackageInstall detects package install commands without
// version pins. Supply chain attacks can inject malicious code through
// unpinned dependencies.
func detectUnpinnedPackageInstall(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		for _, line := range effectiveScripts(job, doc) {
			lower := strings.ToLower(line)

			// Skip lines with lockfile/constraint indicators
			skip := false
			for _, indicator := range packageSkipIndicators {
				if strings.Contains(lower, indicator) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}

			for _, pat := range unpinnedPatterns {
				if pat.re.MatchString(line) && pat.extraCheck(line) {
					findings = append(findings, Finding{
						ID:          UnpinnedPackageInstallID,
						Severity:    SeverityMedium,
						Title:       "Package installed without version pin",
						Description: "Script installs a package without pinning a specific version. Supply chain attacks can inject malicious code through unpinned dependencies.",
						Evidence:    truncateEvidence(line, 200),
						JobName:     job.Name,
					})
					break // one finding per line
				}
			}
		}
	}

	return findings
}
