package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDepConfusion_NpmScopedPrivate(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"npm install @acme-corp/auth-sdk"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, DepConfusionRiskID) {
		t.Fatalf("expected %s, got: %v", DepConfusionRiskID, findingIDs(findings))
	}
}

func TestDepConfusion_NpmPublicScope(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"npm install @types/node @babel/core"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, DepConfusionRiskID) {
		t.Fatalf("expected no dep confusion for public scopes, got: %v", findingIDs(findings))
	}
}

func TestDepConfusion_PipInternal(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"pip install company-internal-utils"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, DepConfusionRiskID) {
		t.Fatalf("expected %s for pip internal, got: %v", DepConfusionRiskID, findingIDs(findings))
	}
}

func TestDepConfusion_GoInternal(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deps",
			Script: []string{"go get company.internal/pkg/auth"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, DepConfusionRiskID) {
		t.Fatalf("expected %s for go internal, got: %v", DepConfusionRiskID, findingIDs(findings))
	}
}

func TestDepConfusion_WithPrivateRegistry(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"npm config set registry $NPM_REGISTRY", "npm install @acme/utils"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, DepConfusionRiskID) {
		t.Fatalf("expected %s, got: %v", DepConfusionRiskID, findingIDs(findings))
	}
	for _, f := range findings {
		if f.ID == DepConfusionRiskID && f.Severity != SeverityHigh {
			t.Fatalf("expected HIGH severity with private registry, got %s", f.Severity)
		}
	}
}
