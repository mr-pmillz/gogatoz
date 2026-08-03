package analyze

import (
	"net"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

var (
	suspiciousDomains = []string{
		".onion",
		"pastebin.com/raw/",
		"hastebin.com/raw/",
		"paste.ee/r/",
		"dpaste.org/",
		"transfer.sh",
		"file.io",
		"0x0.st",
		"temp.sh",
		"ipfs.io",
		"infura-ipfs.io",
		"w3s.link",
		"nft.storage",
		"dweb.link",
		"gateway.pinata.cloud",
		"archive.torproject.org",
		"check.torproject.org",
		"ngrok.io",
		"ngrok-free.app",
		"serveo.net",
		"localhost.run",
		"loca.lt",
		"pipedream.net",
		"webhook.site",
		"requestbin.com",
		"hookbin.com",
		"beeceptor.com",
		"requestcatcher.com",
	}

	ipInURLRe = regexp.MustCompile(`https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?/`)
)

//nolint:gocognit // complexity from distinct domain/IP checks, each straightforward
func detectSuspiciousNetworkTargets(doc *pipeline.Document, feed *config.ThreatIntelFeed) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	domains := suspiciousDomains
	blockedIPs := make(map[string]struct{})
	var blockedHashes []string
	if feed != nil {
		domains = append(domains, feed.BlockedDomains...)
		for _, rawIP := range feed.BlockedIPs {
			if ip := net.ParseIP(strings.TrimSpace(rawIP)); ip != nil {
				blockedIPs[ip.String()] = struct{}{}
			}
		}
		for _, hash := range feed.BlockedHashes {
			if hash = strings.ToLower(strings.TrimSpace(hash)); hash != "" {
				blockedHashes = append(blockedHashes, hash)
			}
		}
	}

	for _, job := range doc.Jobs {
		lines := effectiveScripts(job, doc)
		found := false
		for _, line := range lines {
			if found {
				break
			}
			lower := strings.ToLower(line)
			trimmed := strings.TrimSpace(line)
			if blockedHash := matchingIOCToken(lower, blockedHashes); blockedHash != "" {
				findings = append(findings, Finding{
					ID:          CampaignMatchID,
					Severity:    SeverityCritical,
					Title:       "CI script contains threat-intelligence artifact hash",
					Description: "CI/CD script contains an artifact hash present in the configured threat-intelligence feed. Treat the referenced artifact and every runner that handled it as potentially compromised.",
					Evidence:    stringutil.TruncateEvidence("hash="+blockedHash+" line="+trimmed, 200),
					JobName:     job.Name,
				})
				found = true
				continue
			}

			if !containsHTTPCall(lower) && !strings.Contains(lower, "http") {
				continue
			}

			for _, domain := range domains {
				if strings.Contains(lower, strings.ToLower(domain)) {
					findings = append(findings, Finding{
						ID:          SuspiciousNetworkID,
						Severity:    SeverityHigh,
						Title:       "CI script contacts suspicious domain",
						Description: "CI/CD script makes a request to a suspicious domain (" + domain + "). This may indicate C2 communication, data exfiltration, or use of anonymous relay infrastructure.",
						Evidence:    stringutil.TruncateEvidence("domain="+domain+" line="+trimmed, 200),
						JobName:     job.Name,
					})
					found = true
					break
				}
			}

			if !found {
				if matches := ipInURLRe.FindStringSubmatch(trimmed); len(matches) >= 2 {
					ip := net.ParseIP(matches[1])
					_, feedBlocked := blockedIPs[ip.String()]
					if ip != nil && (feedBlocked || (!isPrivateIP(ip) && !isLoopback(ip))) {
						description := "CI/CD script makes an HTTP request to a public IP address (" + matches[1] + ") rather than a domain name. Direct IP connections bypass DNS monitoring and are commonly used by C2 infrastructure."
						if feedBlocked {
							description = "CI/CD script contacts an IP address present in the configured threat-intelligence feed (" + matches[1] + ")."
						}
						findings = append(findings, Finding{
							ID:          SuspiciousNetworkID,
							Severity:    SeverityHigh,
							Title:       "CI script contacts suspicious IP address",
							Description: description,
							Evidence:    stringutil.TruncateEvidence("ip="+matches[1]+" line="+trimmed, 200),
							JobName:     job.Name,
						})
						found = true
					}
				}
			}
		}
	}
	return findings
}

func matchingIOCToken(text string, indicators []string) string {
	for _, indicator := range indicators {
		for start := 0; start < len(text); {
			offset := strings.Index(text[start:], indicator)
			if offset < 0 {
				break
			}
			index := start + offset
			end := index + len(indicator)
			if (index == 0 || !isIOCTokenChar(text[index-1])) &&
				(end == len(text) || !isIOCTokenChar(text[end])) {
				return indicator
			}
			start = index + 1
		}
	}
	return ""
}

func isIOCTokenChar(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '-'
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"169.254.0.0/16"},
	}
	for _, r := range privateRanges {
		_, cidr, err := net.ParseCIDR(r.network)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}
