// Package bloodhound provides BloodHound-CE OpenGraph integration for
// exporting GitLab CI/CD attack surface data as a navigable graph.
package bloodhound

const (
	Namespace  = "CICD"
	SourceKind = "CICD"
)

// Node kinds
const (
	KindGitLabInstance = "CICD_GitLabInstance"
	KindGroup          = "CICD_Group"
	KindProject        = "CICD_Project"
	KindRunner         = "CICD_Runner"
	KindCIConfig       = "CICD_CIConfig"
	KindJob            = "CICD_Job"
	KindFinding        = "CICD_Finding"
	KindSecret         = "CICD_Secret"
	KindPipeline       = "CICD_Pipeline"
	KindCredential     = "CICD_Credential" //nolint:gosec // graph node kind name, not a credential
)

// Edge kinds
const (
	EdgeContains           = "CICD_Contains"
	EdgeMemberOf           = "CICD_MemberOf"
	EdgeIncludesProject    = "CICD_IncludesProject"
	EdgeIncludesRemote     = "CICD_IncludesRemote"
	EdgeIncludesTemplate   = "CICD_IncludesTemplate"
	EdgeIncludesComponent  = "CICD_IncludesComponent"
	EdgeIncludesLocal      = "CICD_IncludesLocal"
	EdgeRunsOn             = "CICD_RunsOn"
	EdgeHasFinding         = "CICD_HasFinding"
	EdgeHasSecret          = "CICD_HasSecret" //nolint:gosec // graph edge kind name, not a secret
	EdgeExploited          = "CICD_Exploited"
	EdgePivotsTo           = "CICD_PivotsTo"
	EdgeDependsOn          = "CICD_DependsOn"
	EdgeTriggersDownstream = "CICD_TriggersDownstream"
	EdgeSharedRunner       = "CICD_SharedRunner"
)

// Node represents a BloodHound graph node.
type Node struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

// Edge represents a BloodHound graph edge.
type Edge struct {
	Start      EdgeEndpoint   `json:"start"`
	End        EdgeEndpoint   `json:"end"`
	Kind       string         `json:"kind"`
	Properties map[string]any `json:"properties,omitempty"`
}

// EdgeEndpoint references a node by its ID.
type EdgeEndpoint struct {
	Value string `json:"value"`
}

// NewEdge creates an edge between two node IDs.
func NewEdge(startID, endID, kind string) *Edge {
	return &Edge{
		Start: EdgeEndpoint{Value: startID},
		End:   EdgeEndpoint{Value: endID},
		Kind:  kind,
	}
}

// NewEdgeWithProps creates an edge with additional properties.
func NewEdgeWithProps(startID, endID, kind string, props map[string]any) *Edge {
	return &Edge{
		Start:      EdgeEndpoint{Value: startID},
		End:        EdgeEndpoint{Value: endID},
		Kind:       kind,
		Properties: props,
	}
}

// SavedQuery represents a Cypher query to store in BloodHound-CE.
type SavedQuery struct {
	Name        string `json:"name"`
	Query       string `json:"query"`
	Description string `json:"description"`
}

// NodeKindInfo describes a node kind for schema generation.
type NodeKindInfo struct {
	Name          string `json:"name"`
	DisplayName   string `json:"display_name"`
	Description   string `json:"description,omitempty"`
	IsDisplayKind bool   `json:"is_display_kind"`
	Icon          string `json:"icon"`
	Color         string `json:"color"`
}

// RelKindInfo describes a relationship kind for schema generation.
type RelKindInfo struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	IsTraversable bool   `json:"is_traversable"`
}

// AllNodeKinds returns metadata for every custom node kind.
func AllNodeKinds() []NodeKindInfo {
	return []NodeKindInfo{
		{KindGitLabInstance, "GitLab Instance", "A GitLab server instance", true, "server", "#FC6D26"},
		{KindGroup, "GitLab Group", "A GitLab group or subgroup", true, "folder", "#6B4FBB"},
		{KindProject, "GitLab Project", "A GitLab repository project", true, "code-branch", "#1F75CB"},
		{KindRunner, "CI/CD Runner", "A self-hosted GitLab runner", true, "microchip", "#E24329"},
		{KindCIConfig, "CI Configuration", "A .gitlab-ci.yml pipeline config", true, "file-code", "#2E7D32"},
		{KindJob, "CI/CD Job", "A job within a CI/CD pipeline", true, "gear", "#0288D1"},
		{KindFinding, "Security Finding", "A CI/CD security vulnerability finding", true, "bug", "#D32F2F"},
		{KindSecret, "CI/CD Secret", "A CI/CD variable or secret", true, "key", "#F57C00"},
		{KindPipeline, "Pipeline", "A CI/CD pipeline execution", true, "play", "#7B1FA2"},
		{KindCredential, "Credential", "A harvested credential from pivot operations", true, "id-badge", "#C62828"},
	}
}

// AllRelKinds returns metadata for every custom relationship kind.
func AllRelKinds() []RelKindInfo {
	return []RelKindInfo{
		{EdgeContains, "Structural containment (Group->Project, Project->CIConfig, CIConfig->Job)", false},
		{EdgeMemberOf, "Project belongs to Group", false},
		{EdgeIncludesProject, "CI config includes another project's config file", true},
		{EdgeIncludesRemote, "CI config includes a remote URL", true},
		{EdgeIncludesTemplate, "CI config includes a GitLab template", false},
		{EdgeIncludesComponent, "CI config includes a CI/CD component", true},
		{EdgeIncludesLocal, "CI config includes a local file", false},
		{EdgeRunsOn, "Job executes on a specific runner", true},
		{EdgeHasFinding, "Project has a security finding", false},
		{EdgeHasSecret, "Project has a CI/CD secret or variable", false},
		{EdgeExploited, "Attack successfully targeted project", true},
		{EdgePivotsTo, "Credential used to pivot to project", true},
		{EdgeDependsOn, "Transitive dependency through include chains", true},
		{EdgeTriggersDownstream, "Project triggers downstream pipeline", true},
		{EdgeSharedRunner, "Projects share the same runner", true},
	}
}
