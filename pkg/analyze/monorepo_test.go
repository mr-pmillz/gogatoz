package analyze

import "testing"

func TestMonorepoCorrelation_SameMessage(t *testing.T) {
	signals := []MonorepoSignal{
		{ProjectPath: "acme/pkg-a", CommitMessage: "update deps"},
		{ProjectPath: "acme/pkg-b", CommitMessage: "update deps"},
		{ProjectPath: "acme/pkg-c", CommitMessage: "update deps"},
		{ProjectPath: "acme/pkg-d", CommitMessage: "update deps"},
		{ProjectPath: "acme/pkg-e", CommitMessage: "update deps"},
	}
	findings := DetectMonorepoCorrelation(signals)
	if !hasFindingID(findings, MonorepoCorrelationID) {
		t.Fatalf("expected %s for coordinated commits, got: %v", MonorepoCorrelationID, findingIDs(findings))
	}
}

func TestMonorepoCorrelation_DifferentMessages(t *testing.T) {
	signals := []MonorepoSignal{
		{ProjectPath: "acme/pkg-a", CommitMessage: "fix auth"},
		{ProjectPath: "acme/pkg-b", CommitMessage: "add tests"},
		{ProjectPath: "acme/pkg-c", CommitMessage: "refactor logging"},
		{ProjectPath: "acme/pkg-d", CommitMessage: "update docs"},
		{ProjectPath: "acme/pkg-e", CommitMessage: "bump version"},
	}
	findings := DetectMonorepoCorrelation(signals)
	if hasFindingID(findings, MonorepoCorrelationID) {
		t.Fatalf("expected no finding for unrelated commits, got: %v", findingIDs(findings))
	}
}

func TestMonorepoCorrelation_AuthorCIChanges(t *testing.T) {
	signals := []MonorepoSignal{
		{ProjectPath: "acme/pkg-a", AuthorEmail: "attacker@example.com", CIConfigChanged: true},
		{ProjectPath: "acme/pkg-b", AuthorEmail: "attacker@example.com", CIConfigChanged: true},
		{ProjectPath: "acme/pkg-c", AuthorEmail: "attacker@example.com", CIConfigChanged: true},
	}
	findings := DetectMonorepoCorrelation(signals)
	if !hasFindingID(findings, MonorepoCorrelationID) {
		t.Fatalf("expected %s for single author CI changes, got: %v", MonorepoCorrelationID, findingIDs(findings))
	}
}

func TestMonorepoCorrelation_TooFewProjects(t *testing.T) {
	signals := []MonorepoSignal{
		{ProjectPath: "acme/pkg-a", CommitMessage: "update deps"},
		{ProjectPath: "acme/pkg-b", CommitMessage: "update deps"},
	}
	findings := DetectMonorepoCorrelation(signals)
	if hasFindingID(findings, MonorepoCorrelationID) {
		t.Fatalf("expected no finding for <3 projects, got: %v", findingIDs(findings))
	}
}

func TestMonorepoCorrelation_DifferentNamespaces(t *testing.T) {
	signals := []MonorepoSignal{
		{ProjectPath: "acme/pkg-a", CommitMessage: "update deps"},
		{ProjectPath: "beta/pkg-b", CommitMessage: "update deps"},
		{ProjectPath: "gamma/pkg-c", CommitMessage: "update deps"},
	}
	findings := DetectMonorepoCorrelation(signals)
	if hasFindingID(findings, MonorepoCorrelationID) {
		t.Fatalf("expected no finding for different namespaces, got: %v", findingIDs(findings))
	}
}
