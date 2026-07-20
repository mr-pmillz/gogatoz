package bloodhound

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate/report"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

func TestBuilderCreatesInstanceNode(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")
	nodes := b.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (instance), got %d", len(nodes))
	}
	if nodes[0].Kinds[0] != KindGitLabInstance {
		t.Errorf("expected kind %s, got %s", KindGitLabInstance, nodes[0].Kinds[0])
	}
}

func TestBuilderAddEnumerateResults(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")
	results := []enumerate.Result{
		{
			ProjectID:         42,
			ProjectPathWithNS: "group/project-a",
			WebURL:            "https://gitlab.example.com/group/project-a",
			DefaultBranch:     "main",
			StarCount:         10,
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{
					ID:       "SELF_HOSTED_EXPOSED",
					Severity: analyze.SeverityHigh,
					Title:    "Self-hosted runner exposed",
					Evidence: "tags=[shell docker]",
					JobName:  "build",
				},
				{
					ID:       "INCLUDE_PROJECT_UNPINNED",
					Severity: analyze.SeverityHigh,
					Title:    "Unpinned project include",
					Evidence: "project=shared/ci-templates files=[.gitlab-ci.yml]",
					JobName:  "",
				},
			},
			RunnerTagHits: map[string]int{"shell": 1, "docker": 2},
		},
	}

	b.AddEnumerateResults(results)

	nodes := b.Nodes()
	edges := b.Edges()

	nodeKinds := make(map[string]int)
	for _, n := range nodes {
		if len(n.Kinds) > 0 {
			nodeKinds[n.Kinds[0]]++
		}
	}

	if nodeKinds[KindProject] < 1 {
		t.Error("expected at least 1 project node")
	}
	if nodeKinds[KindCIConfig] < 1 {
		t.Error("expected at least 1 CI config node")
	}
	if nodeKinds[KindFinding] != 2 {
		t.Errorf("expected 2 finding nodes, got %d", nodeKinds[KindFinding])
	}
	if nodeKinds[KindRunner] < 1 {
		t.Error("expected runner nodes from tag hits")
	}
	if nodeKinds[KindGroup] < 1 {
		t.Error("expected group node from path")
	}

	edgeKinds := make(map[string]int)
	for _, e := range edges {
		edgeKinds[e.Kind]++
	}
	if edgeKinds[EdgeHasFinding] != 2 {
		t.Errorf("expected 2 HasFinding edges, got %d", edgeKinds[EdgeHasFinding])
	}
	if edgeKinds[EdgeIncludesProject] < 1 {
		t.Error("expected IncludesProject edge from unpinned include finding")
	}
	if edgeKinds[EdgeRunsOn] < 1 {
		t.Error("expected RunsOn edges from runner-related findings")
	}
}

func TestBuilderTransitiveDependencies(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")

	results := []enumerate.Result{
		{
			ProjectID: 1, ProjectPathWithNS: "team/app",
			HasCIPipeline: true,
			Findings: []analyze.Finding{
				{ID: "INCLUDE_PROJECT_UNPINNED", Evidence: "project=shared/templates files=[ci.yml]"},
			},
		},
		{
			ProjectID: 2, ProjectPathWithNS: "shared/templates",
			HasCIPipeline: true,
			Findings: []analyze.Finding{
				{ID: "INCLUDE_PROJECT_UNPINNED", Evidence: "project=infra/base files=[base.yml]"},
			},
		},
		{
			ProjectID: 3, ProjectPathWithNS: "infra/base",
			HasCIPipeline: true,
		},
	}

	b.AddEnumerateResults(results)
	b.BuildTransitiveDependencies()

	edges := b.Edges()
	var dependsOnEdges int
	for _, e := range edges {
		if e.Kind == EdgeDependsOn {
			dependsOnEdges++
		}
	}
	// team/app -> shared/templates (direct)
	// team/app -> infra/base (transitive)
	// shared/templates -> infra/base (direct)
	if dependsOnEdges < 2 {
		t.Errorf("expected at least 2 DependsOn edges (transitive), got %d", dependsOnEdges)
	}
}

func TestBuilderSharedRunnerEdges(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")

	results := []enumerate.Result{
		{
			ProjectID: 1, ProjectPathWithNS: "team/app-a",
			RunnerTagHits: map[string]int{"shared-runner": 3},
		},
		{
			ProjectID: 2, ProjectPathWithNS: "team/app-b",
			RunnerTagHits: map[string]int{"shared-runner": 1},
		},
		{
			ProjectID: 3, ProjectPathWithNS: "other/app-c",
			RunnerTagHits: map[string]int{"private-runner": 1},
		},
	}

	b.AddEnumerateResults(results)
	b.BuildSharedRunnerEdges()

	var sharedEdges int
	for _, e := range b.Edges() {
		if e.Kind == EdgeSharedRunner {
			sharedEdges++
		}
	}
	if sharedEdges != 1 {
		t.Errorf("expected 1 SharedRunner edge (between app-a and app-b), got %d", sharedEdges)
	}
}

func TestBuilderAddAttackResults(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")
	attacks := []report.AttackView{
		{
			PathWithNamespace: "team/target",
			Mode:              "commit_ci",
			Status:            "success",
			PipelineID:        999,
		},
	}
	b.AddAttackResults(attacks)

	nodeKinds := make(map[string]int)
	for _, n := range b.Nodes() {
		if len(n.Kinds) > 0 {
			nodeKinds[n.Kinds[0]]++
		}
	}
	if nodeKinds[KindPipeline] != 1 {
		t.Errorf("expected 1 pipeline node, got %d", nodeKinds[KindPipeline])
	}

	var exploitedEdges int
	for _, e := range b.Edges() {
		if e.Kind == EdgeExploited {
			exploitedEdges++
		}
	}
	if exploitedEdges != 1 {
		t.Errorf("expected 1 Exploited edge, got %d", exploitedEdges)
	}
}

func TestBuilderAddPivotData(t *testing.T) {
	b := NewBuilder("https://gitlab.example.com")
	creds := []store.HarvestedCredential{
		{
			TokenHash:       "abcdef1234567890abcdef1234567890",
			TokenType:       "personal_access_token",
			Username:        "bot-user",
			SourceProjectID: 42,
			Depth:           1,
			IsValid:         true,
		},
	}
	secrets := []store.ExfiltratedSecret{
		{
			SourceProjectID:   42,
			SourceProjectPath: "team/target",
			Key:               "AWS_SECRET",
			Depth:             1,
		},
	}
	b.AddPivotData(creds, secrets)

	nodeKinds := make(map[string]int)
	for _, n := range b.Nodes() {
		if len(n.Kinds) > 0 {
			nodeKinds[n.Kinds[0]]++
		}
	}
	if nodeKinds[KindCredential] != 1 {
		t.Errorf("expected 1 credential node, got %d", nodeKinds[KindCredential])
	}
	if nodeKinds[KindSecret] != 1 {
		t.Errorf("expected 1 secret node, got %d", nodeKinds[KindSecret])
	}
}

func TestExtractTagsFromEvidence(t *testing.T) {
	tests := []struct {
		evidence string
		want     int
	}{
		{"tags=[shell docker]", 2},
		{"tags=[shell_executor]", 1},
		{"tags=[]", 0},
		{"no tags here", 0},
	}
	for _, tt := range tests {
		tags := report.ExtractTagsFromEvidence(tt.evidence)
		if len(tags) != tt.want {
			t.Errorf("report.ExtractTagsFromEvidence(%q) = %d tags, want %d", tt.evidence, len(tags), tt.want)
		}
	}
}

func TestNodeIDDeterminism(t *testing.T) {
	id1 := projectNodeID(42)
	id2 := projectNodeID(42)
	if id1 != id2 {
		t.Errorf("projectNodeID not deterministic: %s != %s", id1, id2)
	}

	id3 := instanceNodeID("https://gitlab.com")
	id4 := instanceNodeID("https://gitlab.com")
	if id3 != id4 {
		t.Errorf("instanceNodeID not deterministic: %s != %s", id3, id4)
	}
}

func TestNodeIDsNoColons(t *testing.T) {
	ids := []string{
		instanceNodeID("https://gitlab.com:8929"),
		projectNodeID(42),
		groupNodeID("some/group"),
		configNodeID(42),
		jobNodeID(42, "build:test"),
		findingNodeID(42, "INCLUDE_REMOTE", "job:name"),
		secretNodeID(42, "MY_SECRET"),
		credentialNodeID("abcdef12345678901234"),
		runnerNodeIDByTag("shell:executor"),
		pipelineNodeID("group/proj", "commit_ci", 999),
		remoteNodeID("https://example.com/ci.yml"),
		componentNodeID("gitlab.com/comp@1.0"),
		projectNodeIDByPath("group/project"),
	}
	for _, id := range ids {
		if contains(id, ":") {
			t.Errorf("node ID contains colon (forbidden by BH-CE): %s", id)
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
