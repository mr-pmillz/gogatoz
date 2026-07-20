package analyze

import (
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

type campaignSignature struct {
	Name        string
	Description string
	Patterns    []campaignPattern
}

type campaignPattern struct {
	re       *regexp.Regexp
	contains string
}

func (p campaignPattern) matches(line string) bool {
	if p.re != nil {
		return p.re.MatchString(line)
	}
	return strings.Contains(strings.ToLower(line), strings.ToLower(p.contains))
}

var knownCampaigns = []campaignSignature{
	{
		Name:        "Hades/GhostAction-style secret dump",
		Description: "Job dumps all environment variables and uploads as artifact with a disguised job name, matching the Hades campaign TTP.",
		Patterns: []campaignPattern{
			{contains: "printenv"},
			{re: regexp.MustCompile(`(?i)(copilot|security|format|diagnostic|optimize|sysdiag)`)},
		},
	},
	{
		Name:        "Artifact-based secret exfiltration",
		Description: "Job writes environment dump to a file whose name matches an artifact path, allowing secret recovery via artifact download.",
		Patterns: []campaignPattern{
			{re: regexp.MustCompile(`(?i)(printenv|env|set)\s*(>|>>)`)},
		},
	},
	{
		Name:        "Worm self-propagation via git",
		Description: "Job clones and pushes to sibling repositories in the same script, matching supply chain worm propagation patterns.",
		Patterns: []campaignPattern{
			{contains: "git clone"},
			{contains: "git push"},
		},
	},
	{
		Name:        "Binary drop-and-execute",
		Description: "Job decodes a payload, makes it executable, and runs it. This matches binary smuggling campaigns like Jscrambler.",
		Patterns: []campaignPattern{
			{re: regexp.MustCompile(`(?i)(base64\s+-d|base64\s+--decode)`)},
			{re: regexp.MustCompile(`(?i)chmod\s+\+x`)},
		},
	},
	{
		Name:        "Reverse shell via CI runner",
		Description: "Job establishes a reverse shell connection from the CI runner, indicating active compromise.",
		Patterns: []campaignPattern{
			{re: regexp.MustCompile(`(?i)(bash\s+-i\s+>&\s*/dev/tcp|nc\s+-[enl]+.*sh|ncat\s+.*-e|socat\s+.*exec|python.*socket.*connect|ruby.*TCPSocket|perl.*socket.*INET)`)},
		},
	},
	{
		Name:        "Credential harvesting via file sweep",
		Description: "Job searches for credential files (SSH keys, cloud configs, browser stores) on the CI runner, matching infostealer campaigns.",
		Patterns: []campaignPattern{
			{re: regexp.MustCompile(`(?i)(\.ssh/id_|\.aws/credentials|\.kube/config|Login\s+Data|key[34]\.db|\.gnupg)`)},
			{re: regexp.MustCompile(`(?i)(curl|wget|tar|zip)`)},
		},
	},
}

func detectCampaignSignatures(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		lines := effectiveScripts(job, doc)
		allText := strings.Join(lines, "\n")
		jobNameLower := strings.ToLower(job.Name)
		combined := allText + "\n" + jobNameLower

		for _, campaign := range knownCampaigns {
			allMatch := true
			for _, p := range campaign.Patterns {
				if !p.matches(combined) {
					allMatch = false
					break
				}
			}
			if allMatch {
				findings = append(findings, Finding{
					ID:          CampaignMatchID,
					Severity:    SeverityCritical,
					Title:       "Matches known campaign: " + campaign.Name,
					Description: campaign.Description,
					Evidence:    stringutil.TruncateEvidence("campaign="+campaign.Name+" job="+job.Name, 200),
					JobName:     job.Name,
				})
				break
			}
		}
	}
	return findings
}
