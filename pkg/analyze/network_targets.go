package analyze

import (
	"net"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
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
func detectSuspiciousNetworkTargets(doc *pipeline.Document) []Finding {
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
			lower := strings.ToLower(line)
			trimmed := strings.TrimSpace(line)

			if !containsHTTPCall(lower) && !strings.Contains(lower, "http") {
				continue
			}

			for _, domain := range suspiciousDomains {
				if strings.Contains(lower, strings.ToLower(domain)) {
					findings = append(findings, Finding{
						ID:          SuspiciousNetworkID,
						Severity:    SeverityHigh,
						Title:       "CI script contacts suspicious domain",
						Description: "CI/CD script makes a request to a suspicious domain (" + domain + "). This may indicate C2 communication, data exfiltration, or use of anonymous relay infrastructure.",
						Evidence:    truncateEvidence("domain="+domain+" line="+trimmed, 200),
						JobName:     job.Name,
					})
					found = true
					break
				}
			}

			if !found {
				if matches := ipInURLRe.FindStringSubmatch(trimmed); len(matches) >= 2 {
					ip := net.ParseIP(matches[1])
					if ip != nil && !isPrivateIP(ip) && !isLoopback(ip) {
						findings = append(findings, Finding{
							ID:          SuspiciousNetworkID,
							Severity:    SeverityHigh,
							Title:       "CI script contacts public IP address directly",
							Description: "CI/CD script makes an HTTP request to a public IP address (" + matches[1] + ") rather than a domain name. Direct IP connections bypass DNS monitoring and are commonly used by C2 infrastructure.",
							Evidence:    truncateEvidence("ip="+matches[1]+" line="+trimmed, 200),
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
