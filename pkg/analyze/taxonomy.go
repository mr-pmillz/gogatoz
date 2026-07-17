package analyze

import "maps"

// CWERef identifies a Common Weakness Enumeration entry.
type CWERef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ATTACKRef identifies a MITRE ATT&CK technique or sub-technique.
type ATTACKRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// OWASPCICDRef identifies an OWASP CI/CD Security Top 10 risk.
type OWASPCICDRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Taxonomy holds all standard vulnerability classification references
// for a finding code.
type Taxonomy struct {
	CWEs          []CWERef       `json:"cwes,omitempty"`
	ATTACKRefs    []ATTACKRef    `json:"attack_refs,omitempty"`
	OWASPCICDRefs []OWASPCICDRef `json:"owasp_cicd_refs,omitempty"`
}

// OWASP CI/CD Top 10 (2023) risk constants.
var (
	owaspSec1  = OWASPCICDRef{ID: "CICD-SEC-1", Name: "Insufficient Flow Control Mechanisms"}
	owaspSec2  = OWASPCICDRef{ID: "CICD-SEC-2", Name: "Inadequate Identity and Access Management"}
	owaspSec3  = OWASPCICDRef{ID: "CICD-SEC-3", Name: "Dependency Chain Abuse"}
	owaspSec4  = OWASPCICDRef{ID: "CICD-SEC-4", Name: "Poisoned Pipeline Execution (PPE)"}
	owaspSec5  = OWASPCICDRef{ID: "CICD-SEC-5", Name: "Insufficient PBAC (Pipeline-Based Access Controls)"}
	owaspSec6  = OWASPCICDRef{ID: "CICD-SEC-6", Name: "Insufficient Credential Hygiene"}
	owaspSec7  = OWASPCICDRef{ID: "CICD-SEC-7", Name: "Insecure System Configuration"}
	owaspSec8  = OWASPCICDRef{ID: "CICD-SEC-8", Name: "Ungoverned Usage of 3rd Party Services"}
	owaspSec9  = OWASPCICDRef{ID: "CICD-SEC-9", Name: "Improper Artifact Integrity Validation"}
	owaspSec10 = OWASPCICDRef{ID: "CICD-SEC-10", Name: "Insufficient Logging and Visibility"}
)

// Commonly referenced CWEs.
var (
	cwe78   = CWERef{ID: 78, Name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"}
	cwe94   = CWERef{ID: 94, Name: "Improper Control of Generation of Code ('Code Injection')"}
	cwe250  = CWERef{ID: 250, Name: "Execution with Unnecessary Privileges"}
	cwe269  = CWERef{ID: 269, Name: "Improper Privilege Management"}
	cwe284  = CWERef{ID: 284, Name: "Improper Access Control"}
	cwe311  = CWERef{ID: 311, Name: "Missing Encryption of Sensitive Data"}
	cwe312  = CWERef{ID: 312, Name: "Cleartext Storage of Sensitive Information"}
	cwe319  = CWERef{ID: 319, Name: "Cleartext Transmission of Sensitive Information"}
	cwe345  = CWERef{ID: 345, Name: "Insufficient Verification of Data Authenticity"}
	cwe346  = CWERef{ID: 346, Name: "Origin Validation Error"}
	cwe367  = CWERef{ID: 367, Name: "Time-of-check Time-of-use (TOCTOU) Race Condition"}
	cwe427  = CWERef{ID: 427, Name: "Uncontrolled Search Path Element"}
	cwe451  = CWERef{ID: 451, Name: "User Interface (UI) Misrepresentation of Critical Information"}
	cwe494  = CWERef{ID: 494, Name: "Download of Code Without Integrity Check"}
	cwe506  = CWERef{ID: 506, Name: "Embedded Malicious Code"}
	cwe522  = CWERef{ID: 522, Name: "Insufficiently Protected Credentials"}
	cwe532  = CWERef{ID: 532, Name: "Insertion of Sensitive Information into Log File"}
	cwe538  = CWERef{ID: 538, Name: "Insertion of Sensitive Information into Externally-Accessible File or Directory"}
	cwe693  = CWERef{ID: 693, Name: "Protection Mechanism Failure"}
	cwe829  = CWERef{ID: 829, Name: "Inclusion of Functionality from Untrusted Control Sphere"}
	cwe913  = CWERef{ID: 913, Name: "Improper Control of Dynamically-Managed Code Resources"}
	cwe915  = CWERef{ID: 915, Name: "Improperly Controlled Modification of Dynamically-Determined Object Attributes"}
	cwe940  = CWERef{ID: 940, Name: "Improper Verification of Source of a Communication Channel"}
	cwe1104 = CWERef{ID: 1104, Name: "Use of Unmaintained Third-Party Components"}
	cwe668  = CWERef{ID: 668, Name: "Exposure of Resource to Wrong Sphere"}
	cwe807  = CWERef{ID: 807, Name: "Reliance on Untrusted Inputs in a Security Decision"}
)

// Commonly referenced MITRE ATT&CK techniques.
var (
	attackT1059     = ATTACKRef{ID: "T1059", Name: "Command and Scripting Interpreter"}
	attackT1078     = ATTACKRef{ID: "T1078", Name: "Valid Accounts"}
	attackT1098     = ATTACKRef{ID: "T1098", Name: "Account Manipulation"}
	attackT1105     = ATTACKRef{ID: "T1105", Name: "Ingress Tool Transfer"}
	attackT1119     = ATTACKRef{ID: "T1119", Name: "Automated Collection"}
	attackT1195_001 = ATTACKRef{ID: "T1195.001", Name: "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"}
	attackT1195_002 = ATTACKRef{ID: "T1195.002", Name: "Supply Chain Compromise: Compromise Software Supply Chain"}
	attackT1199     = ATTACKRef{ID: "T1199", Name: "Trusted Relationship"}
	attackT1204     = ATTACKRef{ID: "T1204", Name: "User Execution"}
	attackT1210     = ATTACKRef{ID: "T1210", Name: "Exploitation of Remote Services"}
	attackT1528     = ATTACKRef{ID: "T1528", Name: "Steal Application Access Token"}
	attackT1550     = ATTACKRef{ID: "T1550", Name: "Use Alternate Authentication Material"}
	attackT1552     = ATTACKRef{ID: "T1552", Name: "Unsecured Credentials"}
	attackT1552_001 = ATTACKRef{ID: "T1552.001", Name: "Unsecured Credentials: Credentials In Files"}
	attackT1553     = ATTACKRef{ID: "T1553", Name: "Subvert Trust Controls"}
	attackT1556     = ATTACKRef{ID: "T1556", Name: "Modify Authentication Process"}
	attackT1562     = ATTACKRef{ID: "T1562", Name: "Impair Defenses"}
	attackT1565_001 = ATTACKRef{ID: "T1565.001", Name: "Data Manipulation: Stored Data Manipulation"}
	attackT1567     = ATTACKRef{ID: "T1567", Name: "Exfiltration Over Web Service"}
	attackT1574     = ATTACKRef{ID: "T1574", Name: "Hijack Execution Flow"}
	attackT1609     = ATTACKRef{ID: "T1609", Name: "Container Administration Command"}
	attackT1610     = ATTACKRef{ID: "T1610", Name: "Deploy Container"}
	attackT1611     = ATTACKRef{ID: "T1611", Name: "Escape to Host"}
	attackT1612     = ATTACKRef{ID: "T1612", Name: "Build Image on Host"}
	attackT1027     = ATTACKRef{ID: "T1027", Name: "Obfuscated Files or Information"}
	attackT1530     = ATTACKRef{ID: "T1530", Name: "Data from Cloud Storage Object"}
)

// taxonomyRegistry maps finding IDs to their standard taxonomy references.
var taxonomyRegistry = map[string]Taxonomy{
	// --- Include risks ---
	IncludeRemoteID: {
		CWEs:          []CWERef{cwe829, cwe494},
		ATTACKRefs:    []ATTACKRef{attackT1195_002, attackT1199},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec8},
	},
	"INCLUDE_PROJECT_UNPINNED": {
		CWEs:          []CWERef{cwe829, cwe345},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec9},
	},
	"INCLUDE_COMPONENT": {
		CWEs:          []CWERef{cwe829, cwe345},
		ATTACKRefs:    []ATTACKRef{attackT1195_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec8},
	},
	IncludeForbiddenVersionID: {
		CWEs:          []CWERef{cwe829, cwe345},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec9},
	},

	// --- Runner exposure ---
	"SELF_HOSTED_EXPOSED": {
		CWEs:          []CWERef{cwe284, cwe250},
		ATTACKRefs:    []ATTACKRef{attackT1078, attackT1210},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7, owaspSec5},
	},
	"MR_TAGGED_RUNNER": {
		CWEs:          []CWERef{cwe284, cwe250},
		ATTACKRefs:    []ATTACKRef{attackT1078, attackT1210},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec5},
	},
	"RUNNER_EXECUTOR_RISK": {
		CWEs:          []CWERef{cwe250, cwe269},
		ATTACKRefs:    []ATTACKRef{attackT1611, attackT1210},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7, owaspSec5},
	},
	"PRIVILEGED_RUNNER_RISK": {
		CWEs:          []CWERef{cwe250, cwe269},
		ATTACKRefs:    []ATTACKRef{attackT1611, attackT1610},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7, owaspSec5},
	},

	// --- Script risks ---
	"RISKY_REMOTE_SCRIPT": {
		CWEs:          []CWERef{cwe829, cwe494},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1105},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec8, owaspSec3},
	},
	"VARIABLE_INJECTION": {
		CWEs:          []CWERef{cwe78, cwe94},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},
	ScriptInjectionRiskID: {
		CWEs:          []CWERef{cwe94, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},

	// --- Secrets ---
	"PLAINTEXT_SECRET": {
		CWEs:          []CWERef{cwe312, cwe522},
		ATTACKRefs:    []ATTACKRef{attackT1552_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6},
	},
	"PLAINTEXT_SECRET_JOB": {
		CWEs:          []CWERef{cwe312, cwe522},
		ATTACKRefs:    []ATTACKRef{attackT1552_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6},
	},
	DebugTraceEnabledID: {
		CWEs:          []CWERef{cwe532, cwe312},
		ATTACKRefs:    []ATTACKRef{attackT1552, attackT1562},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec7},
	},

	// --- Fork / MR risks ---
	"FORK_MR_UNPROTECTED": {
		CWEs:          []CWERef{cwe284, cwe346},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec1},
	},
	"FORK_SCRIPT_EXECUTION": {
		CWEs:          []CWERef{cwe94, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},

	// --- Artifacts ---
	"ARTIFACTS_NO_EXPIRE": {
		CWEs:          []CWERef{cwe538},
		ATTACKRefs:    []ATTACKRef{attackT1119},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9, owaspSec7},
	},
	"ARTIFACT_POISONING_RISK": {
		CWEs:          []CWERef{cwe345, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1195_002, attackT1565_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9, owaspSec4},
	},

	// --- AI risks ---
	"AI_PROMPT_INJECTION": {
		CWEs:          []CWERef{cwe94, cwe913},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1204},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec8},
	},
	AIConfigCredHarvesterID: {
		CWEs:          []CWERef{cwe522, cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1552_001, attackT1204},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec8},
	},
	AIConfigPromptInjEnhancedID: {
		CWEs:          []CWERef{cwe94, cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1567, attackT1204},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec8, owaspSec4},
	},

	// --- Supply chain ---
	SelfMergePossibleID: {
		CWEs:          []CWERef{cwe284, cwe693},
		ATTACKRefs:    []ATTACKRef{attackT1098, attackT1556},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec1, owaspSec2},
	},
	CachePoisoningRiskID: {
		CWEs:          []CWERef{cwe345, cwe915},
		ATTACKRefs:    []ATTACKRef{attackT1565_001, attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9, owaspSec4},
	},

	// --- Workflow ---
	"WORKFLOW_BROAD_RULES": {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1078},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec1, owaspSec5},
	},

	// --- Dispatch / TOCTOU / Pwn Request ---
	"DISPATCH_TOCTOU_RISK": {
		CWEs:          []CWERef{cwe367},
		ATTACKRefs:    []ATTACKRef{attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec1},
	},
	"PWN_REQUEST_DEPLOYMENT": {
		CWEs:          []CWERef{cwe269, cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1078, attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec5},
	},

	// --- LOTP ---
	"LOTP_TOOL_EXEC": {
		CWEs:          []CWERef{cwe94, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec3},
	},
	"CACHE_KEY_INJECTION": {
		CWEs:          []CWERef{cwe915, cwe345},
		ATTACKRefs:    []ATTACKRef{attackT1565_001, attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9, owaspSec4},
	},
	"OIDC_TOKEN_MR_RISK": {
		CWEs:          []CWERef{cwe284, cwe522},
		ATTACKRefs:    []ATTACKRef{attackT1528, attackT1550},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec5},
	},
	OIDCProvenanceAnomalyID: {
		CWEs:          []CWERef{cwe284, cwe940},
		ATTACKRefs:    []ATTACKRef{attackT1528, attackT1553},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec1},
	},
	"TRIGGER_CHAIN_RISK": {
		CWEs:          []CWERef{cwe284, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1199, attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec5, owaspSec4},
	},

	// --- DinD ---
	DinDDetectedID: {
		CWEs:          []CWERef{cwe250, cwe269},
		ATTACKRefs:    []ATTACKRef{attackT1611, attackT1612},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},
	DinDInsecureID: {
		CWEs:          []CWERef{cwe311, cwe319},
		ATTACKRefs:    []ATTACKRef{attackT1609, attackT1552},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},

	// --- Image pinning ---
	"IMAGE_MUTABLE_TAG": {
		CWEs:          []CWERef{cwe345, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec9},
	},
	"IMAGE_NOT_PINNED": {
		CWEs:          []CWERef{cwe345, cwe494},
		ATTACKRefs:    []ATTACKRef{attackT1195_002, attackT1610},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec9},
	},

	// --- Obfuscation / evasion ---
	"SCRIPT_OBFUSCATION": {
		CWEs:          []CWERef{cwe506, cwe451},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1562},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec10},
	},
	ScriptEncodedPayloadID: {
		CWEs:          []CWERef{cwe506, cwe94},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1027},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec10},
	},
	WhitespaceHidingID: {
		CWEs:          []CWERef{cwe451, cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1027},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec10},
	},
	CharcodeObfuscationID: {
		CWEs:          []CWERef{cwe506, cwe94},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1027},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec10},
	},

	// --- Exfiltration ---
	SecretExfilHTTPID: {
		CWEs:          []CWERef{cwe319, cwe522},
		ATTACKRefs:    []ATTACKRef{attackT1567, attackT1552},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec4},
	},
	SecretExfilArtifactID: {
		CWEs:          []CWERef{cwe538, cwe522},
		ATTACKRefs:    []ATTACKRef{attackT1119, attackT1552},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec9},
	},
	WorkflowSecretExfilID: {
		CWEs:          []CWERef{cwe319, cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1567, attackT1552},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec4},
	},
	WorkflowArtifactExfilID: {
		CWEs:          []CWERef{cwe538, cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1119, attackT1552},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec6, owaspSec9},
	},

	// --- Network / campaign ---
	SuspiciousNetworkID: {
		CWEs:          []CWERef{cwe506, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1105, attackT1567},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec8, owaspSec10},
	},
	CampaignMatchID: {
		CWEs:          []CWERef{cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1195_002, attackT1059},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4, owaspSec3},
	},
	MonorepoCorrelationID: {
		CWEs:          []CWERef{cwe506},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec10},
	},

	// --- Variable inheritance risks ---
	VarInheritanceShadowID: {
		CWEs:          []CWERef{cwe807},
		ATTACKRefs:    []ATTACKRef{attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},
	VarUnmaskedSecretID: {
		CWEs:          []CWERef{cwe312},
		ATTACKRefs:    []ATTACKRef{attackT1552_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec2},
	},
	VarUnprotectedSecretID: {
		CWEs:          []CWERef{cwe668},
		ATTACKRefs:    []ATTACKRef{attackT1552_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec2},
	},
	VarMROverrideRiskID: {
		CWEs:          []CWERef{cwe807},
		ATTACKRefs:    []ATTACKRef{attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},

	// --- Environment/deployment risks ---
	EnvUnprotectedDeployID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec5},
	},
	EnvNoApprovalGateID: {
		CWEs:          []CWERef{{ID: 862, Name: "Missing Authorization"}},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec5},
	},
	EnvMRDeployRiskID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3},
	},
	EnvStaleDeploymentID: {
		CWEs:          []CWERef{{ID: 1188, Name: "Initialization with Hard-Coded Network Resource Configuration Data"}},
		ATTACKRefs:    []ATTACKRef{{ID: "T1190", Name: "Exploit Public-Facing Application"}},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},

	// --- Pages risks ---
	PagesPublicDeployID: {
		CWEs:          []CWERef{cwe538},
		ATTACKRefs:    []ATTACKRef{attackT1530},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},
	PagesMRDeployRiskID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3},
	},
	PagesSensitivePathID: {
		CWEs:          []CWERef{cwe538},
		ATTACKRefs:    []ATTACKRef{attackT1530},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},

	// --- SBOM / Supply chain pinning ---
	SBOMUnpinnedImageID: {
		CWEs:          []CWERef{cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9},
	},
	SBOMNoDigestID: {
		CWEs:          []CWERef{cwe345},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9},
	},

	// --- Dependency confusion ---
	DepConfusionRiskID: {
		CWEs:          []CWERef{cwe427, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1195_001, attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3},
	},

	// --- Supply chain script verification ---
	UnverifiedScriptExecID: {
		CWEs:          []CWERef{cwe494, cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1059, attackT1105},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec8, owaspSec9},
	},
	UnpinnedPackageInstallID: {
		CWEs:          []CWERef{cwe494, cwe1104},
		ATTACKRefs:    []ATTACKRef{attackT1195_001},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3, owaspSec9},
	},

	// --- Governance ---
	SecurityJobWeakenedID: {
		CWEs:          []CWERef{cwe693},
		ATTACKRefs:    []ATTACKRef{attackT1562},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec1, owaspSec7},
	},
	JobHardcodedID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1078},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec1, owaspSec7},
	},
}

// LookupTaxonomy returns the taxonomy references for a finding code, or nil
// if no mapping exists.
func LookupTaxonomy(findingID string) *Taxonomy {
	if t, ok := taxonomyRegistry[findingID]; ok {
		return &t
	}
	return nil
}

// AllTaxonomies returns a copy of the full taxonomy registry.
func AllTaxonomies() map[string]Taxonomy {
	out := make(map[string]Taxonomy, len(taxonomyRegistry))
	maps.Copy(out, taxonomyRegistry)
	return out
}
