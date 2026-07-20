package analyze

import (
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const (
	AIConfigCredHarvesterID     = "AI_CONFIG_CREDENTIAL_HARVESTER"      //nolint:gosec // finding ID, not a credential
	AIConfigPromptInjEnhancedID = "AI_CONFIG_PROMPT_INJECTION_ENHANCED" //nolint:gosec // finding ID, not a credential
)

var (
	aiConfigFiles = []string{
		".cursorrules", ".cursor/rules", "cursorrules",
		".claude/settings.json", "claude.json", "CLAUDE.md",
		"copilot-instructions.md", ".github/copilot-instructions.md",
		".copilot-instructions.md",
		".aider.conf.yml", ".continue/config.json",
		".codeium/config.json",
	}

	credentialPaths = []string{
		"~/.ssh", "~/.gitconfig", ".env", "~/.aws/credentials",
		"~/.aws/config", "~/.kube/config", "~/.docker/config.json",
		"~/.npmrc", "~/.pypirc", "~/.netrc", "/etc/shadow",
		"~/.gnupg", "~/.config/gh/hosts.yml",
	}

	aiConfigCreateRe = regexp.MustCompile(`(?i)(?:cat|echo|tee|cp|printf|write)\s+.*(?:>|>>)\s*\S*(?:` +
		strings.Join([]string{
			`\.cursorrules`, `copilot-instructions`, `\.claude`,
			`\.aider`, `\.continue`, `\.codeium`,
		}, "|") + `)`)

	httpExfilInContentRe = regexp.MustCompile(`(?i)(?:curl|wget|fetch|http\.get|requests\.(?:get|post))\s+`)
)

func detectAIConfigHarvesters(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		lines := effectiveScripts(job, doc)
		joined := strings.Join(lines, "\n")
		lower := strings.ToLower(joined)

		createsAIConfig := aiConfigCreateRe.MatchString(joined)
		if !createsAIConfig {
			for _, f := range aiConfigFiles {
				if strings.Contains(lower, f) {
					createsAIConfig = true
					break
				}
			}
		}
		if !createsAIConfig {
			continue
		}

		if hasCredentialSweepPattern(lower) {
			findings = append(findings, Finding{
				ID:       AIConfigCredHarvesterID,
				Severity: SeverityMedium,
				Title:    "AI tool config harvests credentials",
				Description: "This CI job creates or modifies an AI tool configuration file that reads " +
					"credential paths (~/.ssh, ~/.aws/credentials, .env, etc.). This is the Miasma attack " +
					"pattern — credential harvesters disguised as legitimate AI tool configs.",
				Evidence: stringutil.TruncateEvidence("job="+job.Name, 200),
				JobName:  job.Name,
			})
			continue
		}

		if httpExfilInContentRe.MatchString(joined) {
			findings = append(findings, Finding{
				ID:       AIConfigPromptInjEnhancedID,
				Severity: SeverityMedium,
				Title:    "AI tool config makes external HTTP requests",
				Description: "This CI job creates or modifies an AI tool configuration file that includes " +
					"HTTP request patterns. AI configs that make external requests can exfiltrate code context, " +
					"secrets, or developer environment data.",
				Evidence: stringutil.TruncateEvidence("job="+job.Name, 200),
				JobName:  job.Name,
			})
		}
	}
	return findings
}

func hasCredentialSweepPattern(lower string) bool {
	for _, cp := range credentialPaths {
		if strings.Contains(lower, strings.ToLower(cp)) {
			return true
		}
	}
	return false
}
