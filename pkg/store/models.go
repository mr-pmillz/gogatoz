// Package store provides SQLite-backed persistence for MCP scan results
// using GORM. Models are purpose-built for storage and intentionally separate
// from pkg/models (which are reserved for SDK consumers).
package store

import (
	"time"

	"gorm.io/gorm"
)

// ScanSession groups results from a single search or enumerate invocation.
type ScanSession struct {
	gorm.Model
	GitLabURL    string    `gorm:"not null"`
	StartedAt    time.Time `gorm:"not null"`
	FinishedAt   *time.Time
	Status       string `gorm:"not null;default:running"` // running|completed|error
	Error        string
	SearchTotal  int
	EnumTotal    int
	EnumFindings int

	SearchResults    []SearchResult    `gorm:"foreignKey:SessionID;constraint:OnDelete:CASCADE"`
	EnumerateResults []EnumerateResult `gorm:"foreignKey:SessionID;constraint:OnDelete:CASCADE"`
	AttackTotal      int
	AttackSuccess    int
	AttackResults    []AttackResult `gorm:"foreignKey:SessionID;constraint:OnDelete:CASCADE"`

	SecretScanTotal    int
	SecretScanFindings int
	SecretScanResults  []SecretScanResult `gorm:"foreignKey:SessionID;constraint:OnDelete:CASCADE"`
}

// SearchResult stores a single project returned from search_projects.
type SearchResult struct {
	gorm.Model
	SessionID         uint   `gorm:"not null;index"`
	GitLabProjectID   int64  `gorm:"not null;index"`
	PathWithNamespace string `gorm:"not null"`
	WebURL            string
	Visibility        string
	DefaultBranch     string
	StarCount         int64
}

// EnumerateResult stores the scan outcome for a single project.
type EnumerateResult struct {
	gorm.Model
	SessionID         uint   `gorm:"not null;index"`
	GitLabProjectID   int64  `gorm:"not null;index"`
	PathWithNamespace string `gorm:"not null"`
	WebURL            string
	DefaultBranch     string
	StarCount         int64
	HasCIPipeline     bool
	FindingsCount     int
	ProtectedBranches string `gorm:"type:text"` // JSON-encoded []string
	RunnersTotal      int
	RunnersOnline     int
	DurationMS        int64
	Error             string

	Findings []Finding `gorm:"foreignKey:EnumerateResultID;constraint:OnDelete:CASCADE"`
}

// AttackResult stores the outcome of a single attack operation.
type AttackResult struct {
	gorm.Model
	SessionID         uint   `gorm:"not null;index"`
	GitLabProjectID   int64  `gorm:"index"`
	PathWithNamespace string `gorm:"not null"`
	WebURL            string
	Mode              string `gorm:"not null"` // commit_ci, secrets, discover_tags
	Payload           string // ror-shell, pwn-request, ror, secrets, custom
	Branch            string
	PipelineURL       string
	PipelineID        int64
	Tags              string // comma-separated
	Status            string `gorm:"not null;default:success"` // success, error
	Error             string
	DurationMS        int64
}

// AttackExfilSecret stores a single decrypted key/value pair from an exfil artifact download.
type AttackExfilSecret struct {
	gorm.Model
	AttackResultID uint   `gorm:"not null;index"`
	Key            string `gorm:"not null"`
	Value          string `gorm:"not null"` //nolint:gosec
}

// Finding stores a single vulnerability finding from CI/CD analysis.
type Finding struct {
	gorm.Model
	EnumerateResultID uint   `gorm:"not null;index"`
	FindingID         string `gorm:"not null;index"` // e.g. "INCLUDE_REMOTE"
	Severity          string `gorm:"not null"`       // CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL
	Title             string `gorm:"not null"`
	Description       string
	Evidence          string
	JobName           string
	Recommendation    string

	FalsePositive       bool `gorm:"default:false"`
	FalsePositiveReason string
}

// SecretScanResult stores the outcome of secret scanning for a single project.
type SecretScanResult struct {
	gorm.Model
	SessionID         uint   `gorm:"not null;index"`
	GitLabProjectID   int64  `gorm:"index"`
	PathWithNamespace string `gorm:"not null"`
	WebURL            string
	ClonePath         string
	Scanners          string // comma-separated scanner names
	FindingsCount     int
	DurationMS        int64
	Error             string

	SecretFindings []SecretFinding `gorm:"foreignKey:SecretScanResultID;constraint:OnDelete:CASCADE"`
}

// SecretFinding stores a single secret detected by an external scanner.
type SecretFinding struct {
	gorm.Model
	SecretScanResultID uint   `gorm:"not null;index"`
	Scanner            string `gorm:"not null"`
	RuleID             string
	Description        string
	File               string
	Line               int
	Secret             string //nolint:gosec // detected secret value, not a credential
	Entropy            float64
	Commit             string
	Author             string
	Date               string
	Verified           bool
	Severity           string
}

// PivotSession stores the outcome of a single pivot operation.
type PivotSession struct {
	gorm.Model
	SessionID          uint   `gorm:"not null;index"`
	InitialTargets     string `gorm:"type:text"` // JSON array
	MaxDepth           int
	MaxDepthReached    int
	ProjectsEnumerated int
	ProjectsAttacked   int
	CredentialsFound   int
	CredentialsValid   int
	DurationMS         int64
	Status             string // running|completed|error
	Error              string
}

// HarvestedCredential stores metadata about a token found during pivot (no raw token values).
type HarvestedCredential struct {
	gorm.Model
	PivotSessionID  uint   `gorm:"not null;index"`
	TokenHash       string `gorm:"not null;index"` // SHA256, never raw
	TokenType       string
	SourceKey       string
	SourceProjectID int64
	SourcePipeline  int64
	Depth           int
	UserID          int64
	Username        string
	Scopes          string // JSON array
	IsValid         bool
}

// ExfiltratedSecret stores a single key/value pair from an exfiltration callback.
type ExfiltratedSecret struct {
	gorm.Model
	PivotSessionID    uint   `gorm:"not null;index"`
	SourceProjectID   int64  `gorm:"index"`
	SourceProjectPath string `gorm:"not null"`
	Depth             int
	Key               string `gorm:"not null"`
	Value             string `gorm:"not null"` //nolint:gosec // exfiltrated value, not a credential
}

// GraphNode stores a BloodHound graph node for re-export.
type GraphNode struct {
	gorm.Model
	SessionID  uint   `gorm:"not null;index"`
	NodeID     string `gorm:"not null;index"`
	Kind       string `gorm:"not null;index"`
	Properties string `gorm:"type:text"`
}

// GraphEdge stores a BloodHound graph edge for re-export.
type GraphEdge struct {
	gorm.Model
	SessionID  uint   `gorm:"not null;index"`
	StartID    string `gorm:"not null;index"`
	EndID      string `gorm:"not null;index"`
	Kind       string `gorm:"not null;index"`
	Properties string `gorm:"type:text"`
}
