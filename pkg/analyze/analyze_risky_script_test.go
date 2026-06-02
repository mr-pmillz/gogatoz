package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func hasFindingID(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestRiskyRemoteScript_CurlBash(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"curl -fsSL https://example.com/install.sh | bash"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, "RISKY_REMOTE_SCRIPT") {
		t.Fatalf("expected RISKY_REMOTE_SCRIPT finding, got: %+v", findings)
	}
}

func TestRiskyRemoteScript_WgetSh(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "setup",
			Script: []string{"wget -qO- https://example.com/script.sh | sh"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, "RISKY_REMOTE_SCRIPT") {
		t.Fatalf("expected RISKY_REMOTE_SCRIPT finding, got: %+v", findings)
	}
}

func TestRiskyRemoteScript_PowerShellIEX(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "ps",
			Script: []string{"powershell -c \"iwr https://example.com/ps.ps1 | iex\""},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, "RISKY_REMOTE_SCRIPT") {
		t.Fatalf("expected RISKY_REMOTE_SCRIPT finding, got: %+v", findings)
	}
}

func TestRiskyRemoteScript_SafeCurl_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "download",
			Script: []string{"curl -fSL -o file.tar.gz https://example.com/file.tar.gz"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if hasFindingID(findings, "RISKY_REMOTE_SCRIPT") {
		t.Fatalf("did not expect RISKY_REMOTE_SCRIPT finding, got: %+v", findings)
	}
}
