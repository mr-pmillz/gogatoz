package bloodhound

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate/report"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// Builder accumulates scan data and converts it into BloodHound graph
// nodes and edges for the CI/CD attack surface.
type Builder struct {
	gitlabURL  string
	instanceID string
	nodes      map[string]*Node
	edges      []*Edge
	// cross-project dependency tracking for transitive resolution
	projectIncludes map[string][]string // projectPath -> included project paths
	// runner tag -> project IDs for shared runner detection
	runnerTagProjects map[string][]string // runnerTag -> list of project node IDs
	// path -> node ID lookup so include evidence resolves to known projects
	pathToNodeID map[string]string
}

// NewBuilder creates a builder for the given GitLab instance URL.
func NewBuilder(gitlabURL string) *Builder {
	instID := instanceNodeID(gitlabURL)
	b := &Builder{
		gitlabURL:         gitlabURL,
		instanceID:        instID,
		nodes:             make(map[string]*Node),
		edges:             make([]*Edge, 0),
		projectIncludes:   make(map[string][]string),
		runnerTagProjects: make(map[string][]string),
		pathToNodeID:      make(map[string]string),
	}
	b.addNode(&Node{
		ID:    instID,
		Kinds: []string{KindGitLabInstance},
		Properties: map[string]any{
			"name":           gitlabURL,
			"url":            gitlabURL,
			"environmentid":  instID,
			"collected":      true,
		},
	})
	return b
}

// AddSearchResults adds projects discovered via search.
func (b *Builder) AddSearchResults(results []map[string]any) {
	for _, m := range results {
		projID := toInt64(m["id"])
		if projID == 0 {
			continue
		}
		path, _ := m["path_with_namespace"].(string)
		nodeID := projectNodeID(projID)
		b.addNode(&Node{
			ID:    nodeID,
			Kinds: []string{KindProject},
			Properties: map[string]any{
				"name":             path,
				"project_id":       projID,
				"web_url":          m["web_url"],
				"visibility":       m["visibility"],
				"default_branch":   m["default_branch"],
				"star_count":       toInt64(m["star_count"]),
				"environmentid":    b.instanceID,
			},
		})
		b.addEdge(NewEdge(b.instanceID, nodeID, EdgeContains))

		if path != "" {
			b.addGroupChainFromPath(path, nodeID)
		}
	}
}

// AddEnumerateResults adds enumeration data including findings, runner info,
// and CI/CD dependency edges.
func (b *Builder) AddEnumerateResults(results []enumerate.Result) {
	for i := range results {
		r := &results[i]
		if r.ProjectID == 0 {
			continue
		}
		projNodeID := projectNodeID(r.ProjectID)

		b.addNode(&Node{
			ID:    projNodeID,
			Kinds: []string{KindProject},
			Properties: map[string]any{
				"name":             r.ProjectPathWithNS,
				"project_id":       r.ProjectID,
				"web_url":          r.WebURL,
				"default_branch":   r.DefaultBranch,
				"star_count":       r.StarCount,
				"has_ci_pipeline":  r.HasCIPipeline,
				"runners_total":    r.RunnersTotal,
				"runners_online":   r.RunnersOnline,
				"findings_count":   len(r.Findings),
				"environmentid":    b.instanceID,
			},
		})
		b.addEdge(NewEdge(b.instanceID, projNodeID, EdgeContains))

		if r.ProjectPathWithNS != "" {
			b.pathToNodeID[r.ProjectPathWithNS] = projNodeID
			b.addGroupChainFromPath(r.ProjectPathWithNS, projNodeID)
		}

		if r.HasCIPipeline {
			configNodeID := configNodeID(r.ProjectID)
			b.addNode(&Node{
				ID:    configNodeID,
				Kinds: []string{KindCIConfig},
				Properties: map[string]any{
					"name":            fmt.Sprintf("%s/.gitlab-ci.yml", r.ProjectPathWithNS),
					"project_id":      r.ProjectID,
					"environmentid":   b.instanceID,
				},
			})
			b.addEdge(NewEdge(projNodeID, configNodeID, EdgeContains))
		}

		for j := range r.Findings {
			b.addFinding(r, &r.Findings[j])
		}

		b.trackRunnerTags(r, projNodeID)
	}
}

// AddAttackResults adds successful attack data.
func (b *Builder) AddAttackResults(attacks []report.AttackView) {
	for i := range attacks {
		a := &attacks[i]
		if a.PathWithNamespace == "" {
			continue
		}
		pipeID := pipelineNodeID(a.PathWithNamespace, a.Mode, a.PipelineID)
		b.addNode(&Node{
			ID:    pipeID,
			Kinds: []string{KindPipeline},
			Properties: map[string]any{
				"name":          fmt.Sprintf("%s (%s)", a.PathWithNamespace, a.Mode),
				"mode":          a.Mode,
				"payload":       a.Payload,
				"branch":        a.Branch,
				"pipeline_url":  a.PipelineURL,
				"pipeline_id":   a.PipelineID,
				"status":        a.Status,
				"environmentid": b.instanceID,
			},
		})

		projNodeID := projectNodeIDByPath(a.PathWithNamespace)
		if a.Status == "success" {
			b.addEdge(NewEdge(pipeID, projNodeID, EdgeExploited))
		}
	}
}

// AddPivotData adds pivot session data including credential chains.
func (b *Builder) AddPivotData(creds []store.HarvestedCredential, secrets []store.ExfiltratedSecret) {
	for i := range creds {
		c := &creds[i]
		credID := credentialNodeID(c.TokenHash)
		b.addNode(&Node{
			ID:    credID,
			Kinds: []string{KindCredential},
			Properties: map[string]any{
				"name":            fmt.Sprintf("cred-%s (%s)", c.TokenHash[:8], c.TokenType),
				"token_type":      c.TokenType,
				"username":        c.Username,
				"depth":           c.Depth,
				"is_valid":        c.IsValid,
				"source_key":      c.SourceKey,
				"environmentid":   b.instanceID,
			},
		})

		if c.SourceProjectID > 0 {
			srcProjID := projectNodeID(c.SourceProjectID)
			b.addEdge(NewEdge(srcProjID, credID, EdgePivotsTo))
		}
	}

	for i := range secrets {
		s := &secrets[i]
		if s.SourceProjectID > 0 {
			projID := projectNodeID(s.SourceProjectID)
			secretID := secretNodeID(s.SourceProjectID, s.Key)
			b.addNode(&Node{
				ID:    secretID,
				Kinds: []string{KindSecret},
				Properties: map[string]any{
					"name":           s.Key,
					"source_project": s.SourceProjectPath,
					"depth":          s.Depth,
					"environmentid":  b.instanceID,
				},
			})
			b.addEdge(NewEdge(projID, secretID, EdgeHasSecret))
		}
	}
}

// AddSecretScanResults adds secret scan findings.
func (b *Builder) AddSecretScanResults(results []store.SecretScanResult) {
	for i := range results {
		r := &results[i]
		if r.GitLabProjectID > 0 {
			projID := projectNodeID(r.GitLabProjectID)
			for j := range r.SecretFindings {
				f := &r.SecretFindings[j]
				sID := secretNodeID(r.GitLabProjectID, f.RuleID+"-"+f.File)
				b.addNode(&Node{
					ID:    sID,
					Kinds: []string{KindSecret},
					Properties: map[string]any{
						"name":           fmt.Sprintf("%s (%s)", f.RuleID, f.File),
						"scanner":        f.Scanner,
						"rule_id":        f.RuleID,
						"file":           f.File,
						"verified":       f.Verified,
						"severity":       f.Severity,
						"environmentid":  b.instanceID,
					},
				})
				b.addEdge(NewEdge(projID, sID, EdgeHasSecret))
			}
		}
	}
}

// BuildTransitiveDependencies walks the include graph to add CICD_DependsOn
// edges for transitive dependencies.
func (b *Builder) BuildTransitiveDependencies() {
	for srcPath, directDeps := range b.projectIncludes {
		visited := map[string]bool{srcPath: true}
		queue := make([]string, len(directDeps))
		copy(queue, directDeps)

		for len(queue) > 0 {
			depPath := queue[0]
			queue = queue[1:]
			if visited[depPath] {
				continue
			}
			visited[depPath] = true

			srcID := b.resolveProjectByPath(srcPath)
			depID := b.resolveProjectByPath(depPath)
			b.addEdge(NewEdge(srcID, depID, EdgeDependsOn))

			for _, transitive := range b.projectIncludes[depPath] {
				if !visited[transitive] {
					queue = append(queue, transitive)
				}
			}
		}
	}
}

// BuildSharedRunnerEdges creates CICD_SharedRunner edges between projects
// that share runner tags.
func (b *Builder) BuildSharedRunnerEdges() {
	for _, projectIDs := range b.runnerTagProjects {
		if len(projectIDs) < 2 {
			continue
		}
		for i := 0; i < len(projectIDs); i++ {
			for j := i + 1; j < len(projectIDs); j++ {
				b.addEdge(NewEdge(projectIDs[i], projectIDs[j], EdgeSharedRunner))
			}
		}
	}
}

// Nodes returns all accumulated graph nodes.
func (b *Builder) Nodes() []*Node {
	result := make([]*Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		result = append(result, n)
	}
	return result
}

// Edges returns all accumulated graph edges.
func (b *Builder) Edges() []*Edge {
	return b.edges
}

// --- internal helpers ---

func (b *Builder) addNode(n *Node) {
	if existing, ok := b.nodes[n.ID]; ok {
		for k, v := range n.Properties {
			existing.Properties[k] = v
		}
		return
	}
	b.nodes[n.ID] = n
}

func (b *Builder) addEdge(e *Edge) {
	b.edges = append(b.edges, e)
}

func (b *Builder) addGroupChainFromPath(path, projNodeID string) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return
	}
	groupParts := parts[:len(parts)-1]
	parentID := b.instanceID
	for i := range groupParts {
		groupPath := strings.Join(groupParts[:i+1], "/")
		gID := groupNodeID(groupPath)
		b.addNode(&Node{
			ID:    gID,
			Kinds: []string{KindGroup},
			Properties: map[string]any{
				"name":           groupPath,
				"environmentid":  b.instanceID,
			},
		})
		b.addEdge(NewEdge(parentID, gID, EdgeContains))
		parentID = gID
	}
	b.addEdge(NewEdge(projNodeID, parentID, EdgeMemberOf))
}

func (b *Builder) addFinding(r *enumerate.Result, f *analyze.Finding) {
	projNodeID := projectNodeID(r.ProjectID)
	findingID := findingNodeID(r.ProjectID, f.ID, f.JobName)

	b.addNode(&Node{
		ID:    findingID,
		Kinds: []string{KindFinding},
		Properties: map[string]any{
			"name":              fmt.Sprintf("[%s] %s", f.Severity, f.Title),
			"finding_id":        f.ID,
			"severity":          string(f.Severity),
			"title":             f.Title,
			"description":       f.Description,
			"evidence":          f.Evidence,
			"job_name":          f.JobName,
			"recommendation":    f.Recommendation,
			"exploitable":       report.IsExploitable(f.ID),
			"false_positive":    f.FalsePositive,
			"environmentid":     b.instanceID,
		},
	})
	b.addEdge(NewEdge(projNodeID, findingID, EdgeHasFinding))

	b.extractIncludeDependencies(r, f)
}

var (
	reProjectInclude = regexp.MustCompile(`project=(\S+)`)
	reRemoteInclude  = regexp.MustCompile(`remote=(\S+)`)
	reTriggerProject = regexp.MustCompile(`project:(\S+)`)
)

func (b *Builder) extractIncludeDependencies(r *enumerate.Result, f *analyze.Finding) {
	configID := configNodeID(r.ProjectID)

	switch f.ID {
	case "INCLUDE_PROJECT_UNPINNED":
		if m := reProjectInclude.FindStringSubmatch(f.Evidence); len(m) > 1 {
			depPath := m[1]
			depProjID := b.resolveProjectByPath(depPath)
			b.addNode(&Node{
				ID:    depProjID,
				Kinds: []string{KindProject},
				Properties: map[string]any{
					"name":          depPath,
					"environmentid": b.instanceID,
				},
			})
			b.addEdge(NewEdge(configID, depProjID, EdgeIncludesProject))
			b.projectIncludes[r.ProjectPathWithNS] = append(
				b.projectIncludes[r.ProjectPathWithNS], depPath)
		}

	case "INCLUDE_REMOTE", "RISKY_REMOTE_SCRIPT":
		if m := reRemoteInclude.FindStringSubmatch(f.Evidence); len(m) > 1 {
			remoteURL := m[1]
			remoteID := remoteNodeID(remoteURL)
			b.addNode(&Node{
				ID:    remoteID,
				Kinds: []string{KindCIConfig},
				Properties: map[string]any{
					"name":          remoteURL,
					"remote_url":    remoteURL,
					"environmentid": b.instanceID,
				},
			})
			b.addEdge(NewEdge(configID, remoteID, EdgeIncludesRemote))
		}

	case "INCLUDE_COMPONENT":
		compRef := strings.TrimPrefix(f.Evidence, "component=")
		compID := componentNodeID(compRef)
		b.addNode(&Node{
			ID:    compID,
			Kinds: []string{KindCIConfig},
			Properties: map[string]any{
				"name":          compRef,
				"component":     compRef,
				"environmentid": b.instanceID,
			},
		})
		b.addEdge(NewEdge(configID, compID, EdgeIncludesComponent))

	case "TRIGGER_CHAIN_RISK":
		if m := reTriggerProject.FindStringSubmatch(f.Evidence); len(m) > 1 {
			depPath := m[1]
			depProjID := b.resolveProjectByPath(depPath)
			b.addNode(&Node{
				ID:    depProjID,
				Kinds: []string{KindProject},
				Properties: map[string]any{
					"name":          depPath,
					"environmentid": b.instanceID,
				},
			})
			b.addEdge(NewEdge(projectNodeID(r.ProjectID), depProjID, EdgeTriggersDownstream))
			b.projectIncludes[r.ProjectPathWithNS] = append(
				b.projectIncludes[r.ProjectPathWithNS], depPath)
		}
	}
}

func (b *Builder) trackRunnerTags(r *enumerate.Result, projNodeID string) {
	for tag := range r.RunnerTagHits {
		b.runnerTagProjects[tag] = append(b.runnerTagProjects[tag], projNodeID)

		runnerID := runnerNodeIDByTag(tag)
		b.addNode(&Node{
			ID:    runnerID,
			Kinds: []string{KindRunner},
			Properties: map[string]any{
				"name":          tag,
				"tag":           tag,
				"environmentid": b.instanceID,
			},
		})
	}

	for _, f := range r.Findings {
		if (f.ID == "SELF_HOSTED_EXPOSED" || f.ID == "MR_TAGGED_RUNNER") && f.JobName != "" {
			tags := extractTagsFromEvidence(f.Evidence)
			for _, tag := range tags {
				runnerID := runnerNodeIDByTag(tag)
				jID := jobNodeID(r.ProjectID, f.JobName)
				b.addNode(&Node{
					ID:    jID,
					Kinds: []string{KindJob},
					Properties: map[string]any{
						"name":          f.JobName,
						"project_id":    r.ProjectID,
						"environmentid": b.instanceID,
					},
				})
				cID := configNodeID(r.ProjectID)
				b.addEdge(NewEdge(cID, jID, EdgeContains))
				b.addEdge(NewEdge(jID, runnerID, EdgeRunsOn))
			}
		}
	}
}

var reTagList = regexp.MustCompile(`tags=\[([^\]]*)\]`)

func extractTagsFromEvidence(evidence string) []string {
	m := reTagList.FindStringSubmatch(evidence)
	if len(m) < 2 {
		return nil
	}
	raw := strings.Split(m[1], " ")
	var tags []string
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// resolveProjectByPath returns the node ID for a project path, preferring
// a known enumerate-based ID over a hash-based fallback.
func (b *Builder) resolveProjectByPath(path string) string {
	if id, ok := b.pathToNodeID[path]; ok {
		return id
	}
	return projectNodeIDByPath(path)
}

// --- node ID constructors ---

func instanceNodeID(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("cicd-instance-%x", h[:6])
}

func projectNodeID(id int64) string {
	return fmt.Sprintf("cicd-project-%d", id)
}

func projectNodeIDByPath(path string) string {
	h := sha256.Sum256([]byte(path))
	return fmt.Sprintf("cicd-project-path-%x", h[:8])
}

func groupNodeID(path string) string {
	h := sha256.Sum256([]byte(path))
	return fmt.Sprintf("cicd-group-%x", h[:8])
}

func configNodeID(projectID int64) string {
	return fmt.Sprintf("cicd-config-%d", projectID)
}

func jobNodeID(projectID int64, jobName string) string {
	h := sha256.Sum256([]byte(jobName))
	return fmt.Sprintf("cicd-job-%d-%x", projectID, h[:6])
}

func findingNodeID(projectID int64, findingID, jobName string) string {
	h := sha256.Sum256([]byte(findingID + "|" + jobName))
	return fmt.Sprintf("cicd-finding-%d-%x", projectID, h[:6])
}

func secretNodeID(projectID int64, key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("cicd-secret-%d-%x", projectID, h[:6])
}

func credentialNodeID(tokenHash string) string {
	if len(tokenHash) > 16 {
		tokenHash = tokenHash[:16]
	}
	return fmt.Sprintf("cicd-credential-%s", tokenHash)
}

func runnerNodeIDByTag(tag string) string {
	h := sha256.Sum256([]byte(tag))
	return fmt.Sprintf("cicd-runner-tag-%x", h[:6])
}

func pipelineNodeID(path, mode string, pipeID int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", path, mode, pipeID)))
	return fmt.Sprintf("cicd-pipeline-%x", h[:8])
}

func remoteNodeID(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("cicd-remote-%x", h[:8])
}

func componentNodeID(ref string) string {
	h := sha256.Sum256([]byte(ref))
	return fmt.Sprintf("cicd-component-%x", h[:8])
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	default:
		return 0
	}
}
