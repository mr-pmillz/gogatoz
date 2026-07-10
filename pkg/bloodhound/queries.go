package bloodhound

// AttackPathQueries returns pre-built Cypher queries for CI/CD attack path
// analysis in BloodHound-CE. Queries use the :CICD parent label for
// compatibility with BH-CE's custom node kind handling.
func AttackPathQueries() []SavedQuery {
	return []SavedQuery{
		{
			Name:        "GoGatoZ: All Exploitable CI/CD Findings",
			Description: "Projects with exploitable CRITICAL/HIGH CI/CD findings — direct attack targets",
			Query: `MATCH p=(proj:CICD_Project)-[:CICD_HasFinding]->(f:CICD_Finding)
WHERE f.severity IN ['CRITICAL', 'HIGH']
AND f.exploitable = true
RETURN p
LIMIT 500`,
		},
		{
			Name:        "GoGatoZ: Dependency Pwnage Matrix",
			Description: "All transitive dependency chains — compromise upstream to pwn downstream projects",
			Query: `MATCH p=(a:CICD)-[:CICD_DependsOn|CICD_IncludesProject|CICD_TriggersDownstream*1..5]->(b:CICD)
WHERE a <> b
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Cross-Project Include Map",
			Description: "All cross-project CI/CD include relationships — supply chain dependency graph",
			Query: `MATCH p=(c:CICD)-[:CICD_IncludesProject]->(target:CICD)
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Runner Blast Radius",
			Description: "Jobs running on shared runners — compromise one runner to affect all connected projects",
			Query: `MATCH p=(j:CICD)-[:CICD_RunsOn]->(r:CICD)
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Shared Runner Attack Surface",
			Description: "Projects sharing the same runner tags — lateral movement via shared infrastructure",
			Query: `MATCH p=(p1:CICD)-[:CICD_SharedRunner]->(p2:CICD)
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Downstream Trigger Chains",
			Description: "Projects that trigger downstream pipelines — chain reaction attack surface",
			Query: `MATCH p=(a:CICD)-[:CICD_TriggersDownstream]->(b:CICD)
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Remote Include Risk Map",
			Description: "External URL includes — third-party supply chain dependencies",
			Query: `MATCH p=(c:CICD)-[:CICD_IncludesRemote]->(remote:CICD)
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Full CI/CD Attack Surface Graph",
			Description: "Complete attack surface — all projects, configs, jobs, runners, and their relationships",
			Query: `MATCH p=(a:CICD)-[:CICD_Contains|CICD_RunsOn|CICD_IncludesProject|CICD_IncludesRemote|CICD_DependsOn|CICD_TriggersDownstream]->(b:CICD)
WHERE a <> b
RETURN p
LIMIT 300`,
		},
		{
			Name:        "GoGatoZ: Pivot Attack Chains",
			Description: "Credential harvesting paths from pivot operations",
			Query: `MATCH p=(proj:CICD)-[:CICD_PivotsTo]->(cred:CICD)
RETURN p`,
		},
		{
			Name:        "GoGatoZ: Secret and Credential Exposure",
			Description: "All discovered secrets and harvested credentials linked to their source projects",
			Query: `MATCH p=(proj:CICD)-[:CICD_HasSecret]->(s:CICD)
RETURN p`,
		},
	}
}
