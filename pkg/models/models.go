package models

// Secret represents a GitLab CI/CD variable/secret metadata.
// This mirrors the original Python gatox/models/secret.py at a high level,
// but adapted to GitLab terminology. Values are never included.
//
// Note: In GoGatoZ the analyzer/attack modules tend to use lightweight
// structures; this package provides a common shape for API/JSON responses and
// potential future library consumers.
type Secret struct {
	Name          string  `json:"name"`
	Scope         string  `json:"scope,omitempty"`       // project|group|instance|environment
	Environment   string  `json:"environment,omitempty"` // if environment-scoped
	Protected     bool    `json:"protected,omitempty"`
	Masked        bool    `json:"masked,omitempty"`
	Raw           any     `json:"raw,omitempty"`            // provider-native metadata if available
	SelectedRepos []int64 `json:"selected_repos,omitempty"` // for group-level selected projects
}

// Runner models a GitLab Runner of interest (usually self-hosted) discovered
// via configuration or logs.
type Runner struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	RunnerType       string   `json:"runner_type,omitempty"` // shared|group|project|instance
	Tags             []string `json:"tags,omitempty"`
	Executor         string   `json:"executor,omitempty"` // docker|shell|kubernetes|custom|...
	OS               string   `json:"os,omitempty"`
	Status           string   `json:"status,omitempty"` // online|offline|paused|...
	NonEphemeral     bool     `json:"non_ephemeral,omitempty"`
	TokenPermissions string   `json:"token_permissions,omitempty"`
}

// Repository is a lightweight representation of a GitLab project important to
// enumeration and reporting.
type Repository struct {
	ProjectID         int64  `json:"project_id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url,omitempty"`
	DefaultBranch     string `json:"default_branch,omitempty"`
}

// Organization maps to a GitLab Group or subgroup.
type Organization struct {
	GroupID  int64  `json:"group_id,omitempty"`
	FullPath string `json:"full_path,omitempty"`
	WebURL   string `json:"web_url,omitempty"`
	ParentID int64  `json:"parent_id,omitempty"`
}

// Execution tracks a high-level run/session for enumeration or attacks.
// This is intentionally small; callers can extend as needed.
type Execution struct {
	ID         string `json:"id"`
	StartedAt  int64  `json:"started_at_unix"`
	FinishedAt int64  `json:"finished_at_unix,omitempty"`
	Status     string `json:"status,omitempty"` // running|success|error
	Error      string `json:"error,omitempty"`
}

// Composite is a tiny helper to compose related objects in responses.
// Prefer direct composition in other structs when possible.
type Composite struct {
	Organization *Organization `json:"organization,omitempty"`
	Repository   *Repository   `json:"repository,omitempty"`
	Runner       *Runner       `json:"runner,omitempty"`
	Secrets      []Secret      `json:"secrets,omitempty"`
}
