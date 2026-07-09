package bloodhound

// AttackPathQueries returns pre-built Cypher queries for CI/CD attack path
// analysis in BloodHound-CE.
func AttackPathQueries() []SavedQuery {
	return []SavedQuery{
		{
			Name:        "GoGatoZ: All Exploitable CI/CD Attack Paths",
			Description: "Find all projects with exploitable CI/CD findings (CRITICAL/HIGH severity)",
			Query: `MATCH (proj:CICD_Project)-[:CICD_HasFinding]->(f:CICD_Finding)
WHERE f.severity IN ['CRITICAL', 'HIGH']
AND f.exploitable = true
RETURN proj, f
ORDER BY f.severity DESC
LIMIT 500`,
		},
		{
			Name:        "GoGatoZ: Shortest Path to Highest Starred Projects",
			Description: "Find attack paths from any project to high-star projects via dependency chains",
			Query: `MATCH (source:CICD_Project), (target:CICD_Project)
WHERE source <> target AND target.star_count > 100
MATCH p = shortestPath((source)-[:CICD_IncludesProject|CICD_DependsOn|CICD_TriggersDownstream|CICD_SharedRunner*1..10]->(target))
RETURN p
ORDER BY target.star_count DESC
LIMIT 100`,
		},
		{
			Name:        "GoGatoZ: Dependency Chain Depth",
			Description: "Show the deepest transitive dependency chains between projects",
			Query: `MATCH p=(a:CICD_Project)-[:CICD_DependsOn*1..10]->(b:CICD_Project)
RETURN a.name AS source, b.name AS target, length(p) AS depth
ORDER BY depth DESC
LIMIT 100`,
		},
		{
			Name:        "GoGatoZ: Runner Blast Radius",
			Description: "Projects sharing the same self-hosted runner — compromise one, affect all",
			Query: `MATCH (r:CICD_Runner)<-[:CICD_RunsOn]-(j:CICD_Job)<-[:CICD_Contains]-(c:CICD_CIConfig)<-[:CICD_Contains]-(p:CICD_Project)
WITH r, collect(DISTINCT p) AS projects
WHERE size(projects) > 1
RETURN r.name AS runner, [p IN projects | p.name] AS affected_projects, size(projects) AS blast_radius
ORDER BY blast_radius DESC`,
		},
		{
			Name:        "GoGatoZ: Secret Exposure via Dependency Chain",
			Description: "Secrets reachable through transitive dependency includes",
			Query: `MATCH (s:CICD_Secret)<-[:CICD_HasSecret]-(target:CICD_Project)<-[:CICD_DependsOn*1..5]-(attacker:CICD_Project)
WHERE attacker <> target
RETURN attacker.name AS entry_point, target.name AS secret_holder, s.name AS secret_name
LIMIT 100`,
		},
		{
			Name:        "GoGatoZ: Pivot Attack Chains",
			Description: "Credential harvesting chains from pivot operations",
			Query: `MATCH p=(proj:CICD_Project)-[:CICD_PivotsTo]->(cred:CICD_Credential)
RETURN p
ORDER BY cred.depth DESC
LIMIT 100`,
		},
		{
			Name:        "GoGatoZ: Projects with Most Downstream Dependents",
			Description: "Most-depended-on projects — highest impact if compromised",
			Query: `MATCH (dep:CICD_Project)-[:CICD_DependsOn*1..10]->(target:CICD_Project)
WITH target, count(DISTINCT dep) AS dependents
RETURN target.name AS project, dependents
ORDER BY dependents DESC
LIMIT 50`,
		},
		{
			Name:        "GoGatoZ: Cross-Project Include Map",
			Description: "All cross-project CI/CD include relationships",
			Query: `MATCH (c:CICD_CIConfig)-[:CICD_IncludesProject]->(target:CICD_Project)
MATCH (source:CICD_Project)-[:CICD_Contains]->(c)
RETURN source.name AS includes_from, target.name AS includes_to
ORDER BY includes_from`,
		},
		{
			Name:        "GoGatoZ: Exploitable Projects via Shared Runners",
			Description: "Projects with exploitable findings that share runners with other projects",
			Query: `MATCH (p1:CICD_Project)-[:CICD_SharedRunner]-(p2:CICD_Project)
MATCH (p1)-[:CICD_HasFinding]->(f:CICD_Finding)
WHERE f.exploitable = true
RETURN p1.name AS vulnerable_project, p2.name AS blast_target, f.title AS finding, f.severity
ORDER BY f.severity DESC`,
		},
		{
			Name:        "GoGatoZ: Remote Include Risk Map",
			Description: "All remote URL includes — external supply chain dependencies",
			Query: `MATCH (c:CICD_CIConfig)-[:CICD_IncludesRemote]->(remote:CICD_CIConfig)
MATCH (proj:CICD_Project)-[:CICD_Contains]->(c)
RETURN proj.name AS project, remote.name AS remote_url
ORDER BY proj.name`,
		},
	}
}
