package artifactverify

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const (
	ExecutionTriggerID     = analyze.PackageExecutionTriggerID
	PersistenceIndicatorID = analyze.PackagePersistenceID
	ExecutablePayloadID    = analyze.PackageExecutableID
	PackageObfuscationID   = analyze.PackageObfuscationID
)

var (
	numericCharCodeContentRe = regexp.MustCompile(
		`(?i)\[\s*(?:\d{1,3}\s*,\s*){5,}\d{1,3}\s*,?\s*\].{0,160}String\.fromCharCode`,
	)
	detachedChildRe = regexp.MustCompile(
		`(?i)detached\s*:\s*true|start_new_session\s*=\s*true|DETACHED_PROCESS|setsid\s*\(`,
	)
)

func analyzeFiles(files []FileRecord) []analyze.Finding {
	findings := make([]analyze.Finding, 0)
	entryFiles := packageEntryFiles(files)
	for _, file := range files {
		lowerPath := strings.ToLower(file.Path)
		base := strings.ToLower(path.Base(file.Path))
		content := string(file.content)

		if isDeveloperToolPersistencePath(lowerPath, base) {
			findings = append(findings, packageFinding(
				PersistenceIndicatorID, analyze.SeverityHigh,
				"Package writes a developer-tool persistence path",
				"A package archive contains a file loaded automatically by an IDE, AI coding agent, desktop developer tool, or global npm CLI.",
				"trigger=developer_tool_path path="+file.Path, file.Path,
			))
		}
		if base == "binding.gyp" {
			findings = append(findings, packageFinding(
				ExecutionTriggerID, analyze.SeverityHigh,
				"Package contains an implicit native build hook",
				"npm may invoke node-gyp for binding.gyp even when package.json has no lifecycle script.",
				"trigger=binding.gyp path="+file.Path, file.Path,
			))
		}
		if strings.HasSuffix(lowerPath, ".pth") {
			severity := analyze.SeverityMedium
			if hasPTHImport(file.content) {
				severity = analyze.SeverityHigh
			}
			findings = append(findings, packageFinding(
				ExecutionTriggerID, severity,
				"Python path file can execute during interpreter startup",
				"A .pth file can add import paths and lines beginning with import execute automatically when Python initializes site packages.",
				"trigger=python_pth path="+file.Path, file.Path,
			))
		}
		if isSystemPersistencePath(lowerPath) {
			findings = append(findings, packageFinding(
				PersistenceIndicatorID, analyze.SeverityHigh,
				"Package contains an operating-system persistence artifact",
				"Cron and systemd artifacts can establish recurring execution outside the package lifecycle.",
				"trigger=os_persistence path="+file.Path, file.Path,
			))
		}
		if detachedChildRe.MatchString(content) {
			findings = append(findings, packageFinding(
				PersistenceIndicatorID, analyze.SeverityHigh,
				"Package launches a detached child process",
				"Detached child processes can outlive the installing or importing process and are a package persistence signal.",
				"trigger=detached_child path="+file.Path, file.Path,
			))
		}
		if numericCharCodeContentRe.Match(file.content) {
			findings = append(findings, packageFinding(
				PackageObfuscationID, analyze.SeverityMedium,
				"Package reconstructs strings from a numeric byte array",
				"Numeric arrays mapped through String.fromCharCode can conceal network destinations and other security-sensitive strings.",
				"technique=numeric_array_from_char_code path="+file.Path, file.Path,
			))
		}
		if isImportEntry(lowerPath, entryFiles) && hasImportTimeBehavior(content) {
			findings = append(findings, packageFinding(
				ExecutionTriggerID, analyze.SeverityHigh,
				"Package entry point performs security-sensitive work on import",
				"The package entry point contains process, network, or dynamic-code primitives that may run when consumers import it.",
				"trigger=import_time path="+file.Path, file.Path,
			))
		}
		if isExecutableMagic(file.Magic) || file.Mode&0o111 != 0 {
			reason := "executable_mode"
			severity := analyze.SeverityMedium
			if isExecutableMagic(file.Magic) {
				reason = "executable_magic"
				severity = analyze.SeverityHigh
			}
			if magicExtensionMismatch(lowerPath, file.Magic) {
				reason = "magic_extension_mismatch"
				severity = analyze.SeverityHigh
			}
			findings = append(findings, packageFinding(
				ExecutablePayloadID, severity,
				"Package contains an executable payload",
				"Executable package members require source, platform, and integrity verification before distribution.",
				"reason="+reason+" magic="+file.Magic+" path="+file.Path, file.Path,
			))
		}
	}
	return append(findings, lifecycleFindings(files)...)
}

func lifecycleFindings(files []FileRecord) []analyze.Finding {
	var findings []analyze.Finding
	for _, file := range files {
		if strings.ToLower(path.Base(file.Path)) != "package.json" {
			continue
		}
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(file.content, &manifest) != nil {
			continue
		}
		for _, hook := range []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"} {
			command := strings.TrimSpace(manifest.Scripts[hook])
			if command == "" {
				continue
			}
			findings = append(findings, packageFinding(
				ExecutionTriggerID, analyze.SeverityHigh,
				"Package defines an install or publish lifecycle hook",
				"Package lifecycle hooks execute automatically in common install and publishing workflows.",
				stringutil.TruncateEvidence("trigger=lifecycle hook="+hook+" command="+command, 300), file.Path,
			))
		}
	}
	return findings
}

func packageEntryFiles(files []FileRecord) map[string]struct{} {
	entries := make(map[string]struct{})
	for _, file := range files {
		if strings.ToLower(path.Base(file.Path)) != "package.json" {
			continue
		}
		var manifest struct {
			Main   string `json:"main"`
			Module string `json:"module"`
		}
		if json.Unmarshal(file.content, &manifest) != nil {
			continue
		}
		dir := path.Dir(strings.ToLower(file.Path))
		for _, entry := range []string{manifest.Main, manifest.Module} {
			entry = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(entry)), "./")
			if entry != "" {
				entries[path.Join(dir, entry)] = struct{}{}
			}
		}
	}
	return entries
}

func isImportEntry(lowerPath string, entries map[string]struct{}) bool {
	if path.Base(lowerPath) == "__init__.py" {
		return true
	}
	_, ok := entries[lowerPath]
	return ok
}

func hasImportTimeBehavior(content string) bool {
	lower := strings.ToLower(content)
	patterns := []string{
		"child_process", ".spawn(", ".exec(", "subprocess.", "os.system(",
		"https.request", "http.request", "fetch(", "requests.get(", "requests.post(",
		"socket.io", "eval(", "exec(",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func hasPTHImport(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "import ") {
			return true
		}
	}
	return false
}

func isDeveloperToolPersistencePath(lowerPath, base string) bool {
	patterns := []string{
		"/.claude/", "/.cursor/rules/", "/.codex/", "/.gemini/", "/.kiro/",
		"/.vscode/tasks.json", "/.vscode/setup.mjs", "/.github/setup.js",
		"/node_modules/@vscode/deviceid/", "/github desktop/", "/lib/node_modules/npm/",
	}
	if base == "agents.md" || base == "gemini.md" || strings.HasSuffix(lowerPath, "/npm-cli.js") {
		return true
	}
	for _, pattern := range patterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func isSystemPersistencePath(lowerPath string) bool {
	base := path.Base(lowerPath)
	return strings.Contains(lowerPath, "/systemd/") || strings.Contains(lowerPath, "/cron") ||
		strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".timer") || strings.HasSuffix(base, ".cron")
}

func isExecutableMagic(magic string) bool {
	return magic == "elf" || magic == "pe" || magic == "mach-o"
}

func magicExtensionMismatch(lowerPath, magic string) bool {
	ext := strings.ToLower(path.Ext(lowerPath))
	switch magic {
	case "elf", "mach-o":
		return ext != "" && ext != ".bin" && ext != ".so" && ext != ".dylib" && ext != ".node"
	case "pe":
		return ext != ".exe" && ext != ".dll"
	case "png":
		return ext != ".png"
	default:
		return false
	}
}

func packageFinding(id string, severity analyze.Severity, title, description, evidence, source string) analyze.Finding {
	recommendation := "Review and remediate this package artifact finding before release or installation."
	if info := analyze.LookupFinding(id); info != nil {
		recommendation = info.Remediation
	}
	return analyze.Finding{
		ID: id, Severity: severity, Title: title, Description: description,
		Evidence: stringutil.TruncateEvidence(evidence, 500), SourceFile: source,
		Recommendation: recommendation,
	}
}
