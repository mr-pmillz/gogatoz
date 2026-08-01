package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

const maxProbeResponseBytes = 1 << 20

// CapabilityStatus describes how strongly GoGatoZ can establish a capability.
type CapabilityStatus string

const (
	StatusConfirmed CapabilityStatus = "confirmed"
	StatusInferred  CapabilityStatus = "inferred"
	StatusDenied    CapabilityStatus = "denied"
	StatusUnknown   CapabilityStatus = "unknown"
)

// Capability represents a directly probed or safely inferred token capability.
type Capability struct {
	Name       string           `json:"name"`
	Category   string           `json:"category,omitempty"`
	Endpoint   string           `json:"endpoint,omitempty"`
	Method     string           `json:"method,omitempty"`
	Accessible bool             `json:"accessible"` // backward-compatible summary
	Status     CapabilityStatus `json:"status"`
	Confidence string           `json:"confidence"`
	Evidence   []string         `json:"evidence,omitempty"`
	Detail     string           `json:"detail,omitempty"`
}

// ProjectAccess summarizes the token owner's effective access to an optional
// target project. It is derived only from read-only project metadata.
type ProjectAccess struct {
	ID              int64  `json:"id"`
	Path            string `json:"path_with_namespace"`
	DefaultBranch   string `json:"default_branch,omitempty"`
	AccessLevel     int    `json:"access_level"`
	AccessLevelName string `json:"access_level_name"`
}

// TokenProfile holds the full result of token validation and scope probing.
type TokenProfile struct {
	TokenName            string         `json:"token_name,omitempty"`
	Scopes               []string       `json:"scopes,omitempty"`
	ScopesKnown          bool           `json:"scopes_known"`
	ExpiresAt            string         `json:"expires_at,omitempty"`
	UserID               int64          `json:"user_id"`
	Username             string         `json:"username"`
	Name                 string         `json:"name"`
	IsAdmin              bool           `json:"is_admin"`
	ProbeMode            string         `json:"probe_mode"`
	ReadOnly             bool           `json:"read_only"`
	HighestProjectAccess int            `json:"highest_project_access,omitempty"`
	HighestAccessName    string         `json:"highest_project_access_name,omitempty"`
	Project              *ProjectAccess `json:"project,omitempty"`
	Capabilities         []Capability   `json:"capabilities"`
}

// ProbeOptions controls optional read-only capability enrichment.
type ProbeOptions struct {
	Project string
}

// ProbeToken validates a GitLab token and maps its effective capabilities with
// read-only requests. For project-specific inference, use ProbeTokenWithOptions.
func ProbeToken(ctx context.Context, client *gitlabx.Client) (*TokenProfile, error) {
	return ProbeTokenWithOptions(ctx, client, ProbeOptions{})
}

// ProbeTokenWithOptions validates a GitLab token using GET requests only. It
// never creates, updates, deletes, rotates, pushes, or triggers resources.
func ProbeTokenWithOptions(
	ctx context.Context,
	client *gitlabx.Client,
	opts ProbeOptions,
) (*TokenProfile, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	p := &TokenProfile{ProbeMode: "read-only", ReadOnly: true}

	probePATSelf(ctx, client, p)
	if err := probeUser(ctx, client, p); err != nil {
		return nil, fmt.Errorf("probe user identity: %w", err)
	}

	direct, access := probeDirectCapabilities(ctx, client)
	if p.IsAdmin {
		access.Known = true
		access.Highest = 50
	}
	p.HighestProjectAccess = access.Highest
	p.HighestAccessName = accessLevelName(access.Highest)
	p.Capabilities = append(p.Capabilities, direct...)
	p.Capabilities = append(p.Capabilities, inferGlobalCapabilities(p, access)...)

	if project := strings.TrimSpace(opts.Project); project != "" {
		projectCaps, projectAccess := probeTargetProject(ctx, client, p, project)
		p.Project = projectAccess
		p.Capabilities = append(p.Capabilities, projectCaps...)
	}
	slog.Debug("token capability probe completed", "user_id", p.UserID,
		"capabilities", len(p.Capabilities), "target_project", strings.TrimSpace(opts.Project))
	return p, nil
}

func probePATSelf(ctx context.Context, client *gitlabx.Client, p *TokenProfile) {
	result := apiGet(ctx, client, "/api/v4/personal_access_tokens/self")
	if result.Status != http.StatusOK || result.Err != nil {
		slog.Debug("PAT self-introspection unavailable", "status", result.Status, "error", result.Err)
		return
	}
	var pat struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := json.Unmarshal(result.Body, &pat); err != nil {
		slog.Debug("PAT self-introspection decode failed", "error", err)
		return
	}
	p.TokenName = pat.Name
	p.Scopes = append([]string(nil), pat.Scopes...)
	p.ScopesKnown = true
	p.ExpiresAt = pat.ExpiresAt
}

func probeUser(ctx context.Context, client *gitlabx.Client, p *TokenProfile) error {
	result := apiGet(ctx, client, "/api/v4/user")
	if result.Err != nil {
		return result.Err
	}
	if result.Status != http.StatusOK {
		return fmt.Errorf("cannot identify token owner (HTTP %d)", result.Status)
	}
	var user struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(result.Body, &user); err != nil {
		return fmt.Errorf("parse user response: %w", err)
	}
	p.UserID = user.ID
	p.Username = user.Username
	p.Name = user.Name
	p.IsAdmin = user.IsAdmin
	return nil
}

type probeSpec struct {
	name     string
	category string
	endpoint string
	detail   func(body []byte) string
}

type accessSummary struct {
	Known   bool
	Highest int
}

func probeDirectCapabilities(ctx context.Context, client *gitlabx.Client) ([]Capability, accessSummary) {
	specs := []probeSpec{
		{"List Projects (member)", "projects", "/api/v4/projects?membership=true&per_page=100", countDetail("projects")},
		{"List Groups", "groups", "/api/v4/groups?per_page=1", countDetail("groups")},
		{"List Users", "users", "/api/v4/users?per_page=1", countDetail("users")},
		{"Admin Runners", "administration", "/api/v4/runners/all?per_page=1", countDetail("runners")},
		{"Admin Settings", "administration", "/api/v4/application/settings", nil},
	}
	caps := make([]Capability, 0, len(specs))
	access := accessSummary{}
	for _, spec := range specs {
		result := apiGet(ctx, client, spec.endpoint)
		capability := capabilityFromHTTP(spec, result)
		caps = append(caps, capability)
		if spec.name == "List Projects (member)" && result.Status == http.StatusOK && result.Err == nil {
			access = summarizeProjectAccess(result.Body)
		}
	}
	return caps, access
}

func capabilityFromHTTP(spec probeSpec, result apiResult) Capability {
	status, confidence := classifyHTTPResult(result)
	detail := ""
	if status == StatusConfirmed && spec.detail != nil {
		detail = spec.detail(result.Body)
	}
	evidence := []string{fmt.Sprintf("GET %s returned HTTP %d", spec.endpoint, result.Status)}
	if result.Err != nil {
		evidence = []string{"GET request failed before an HTTP response"}
	}
	return newCapability(spec.name, spec.category, spec.endpoint, http.MethodGet,
		status, confidence, evidence, detail)
}

func classifyHTTPResult(result apiResult) (CapabilityStatus, string) {
	if result.Err != nil || result.Status == 0 || result.Status == http.StatusNotFound ||
		result.Status == http.StatusTooManyRequests || result.Status >= http.StatusInternalServerError {
		return StatusUnknown, "low"
	}
	if result.Status >= http.StatusOK && result.Status < http.StatusMultipleChoices {
		return StatusConfirmed, "high"
	}
	if result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden {
		return StatusDenied, "high"
	}
	return StatusUnknown, "low"
}

func summarizeProjectAccess(body []byte) accessSummary {
	var projects []struct {
		Permissions projectPermissions `json:"permissions"`
	}
	if err := json.Unmarshal(body, &projects); err != nil {
		return accessSummary{}
	}
	summary := accessSummary{Known: true}
	for _, project := range projects {
		if level := project.Permissions.accessLevel(); level > summary.Highest {
			summary.Highest = level
		}
	}
	return summary
}

func inferGlobalCapabilities(p *TokenProfile, access accessSummary) []Capability {
	return []Capability{
		inferScopedCapability("Read API", "api", p, []string{"api", "read_api", "read_user"}, 0, access),
		inferScopedCapability("Read repositories", "repository", p,
			[]string{"api", "read_api", "read_repository", "write_repository"}, 0, access),
		inferScopedCapability("Write repositories", "repository", p,
			[]string{"api", "write_repository"}, 30, access),
		inferScopedCapability("Create runners", "runners", p,
			[]string{"api", "create_runner"}, 40, access),
		inferScopedCapability("Manage runners", "runners", p,
			[]string{"api", "manage_runner"}, 40, access),
		inferScopedCapability("Sudo API", "administration", p,
			[]string{"sudo"}, 50, access),
	}
}

func inferScopedCapability(
	name string,
	category string,
	p *TokenProfile,
	acceptedScopes []string,
	minimumAccess int,
	access accessSummary,
) Capability {
	evidence := []string{}
	matchingScope := firstMatchingScope(p.Scopes, acceptedScopes)
	if !p.ScopesKnown {
		return newCapability(name, category, "", "inference", StatusUnknown, "low",
			[]string{"token scopes unavailable from PAT self-introspection"}, "")
	}
	if matchingScope == "" {
		return newCapability(name, category, "", "inference", StatusDenied, "high",
			[]string{"required token scope not declared: " + strings.Join(acceptedScopes, " or ")}, "")
	}
	evidence = append(evidence, "declared token scope: "+matchingScope)
	if minimumAccess == 0 {
		return newCapability(name, category, "", "inference", StatusInferred, "medium", evidence, "")
	}
	if !access.Known {
		evidence = append(evidence, "project access level unavailable")
		return newCapability(name, category, "", "inference", StatusUnknown, "low", evidence, "")
	}
	evidence = append(evidence, fmt.Sprintf("highest observed project access: %s (%d)",
		accessLevelName(access.Highest), access.Highest))
	if access.Highest < minimumAccess {
		return newCapability(name, category, "", "inference", StatusDenied, "high", evidence, "")
	}
	return newCapability(name, category, "", "inference", StatusInferred, "medium", evidence, "")
}

type projectPermissions struct {
	ProjectAccess *struct {
		AccessLevel int `json:"access_level"`
	} `json:"project_access"`
	GroupAccess *struct {
		AccessLevel int `json:"access_level"`
	} `json:"group_access"`
}

func (permissions projectPermissions) accessLevel() int {
	level := 0
	if permissions.ProjectAccess != nil {
		level = permissions.ProjectAccess.AccessLevel
	}
	if permissions.GroupAccess != nil && permissions.GroupAccess.AccessLevel > level {
		level = permissions.GroupAccess.AccessLevel
	}
	return level
}

type targetProjectResponse struct {
	ID            int64              `json:"id"`
	Path          string             `json:"path_with_namespace"`
	DefaultBranch string             `json:"default_branch"`
	Permissions   projectPermissions `json:"permissions"`
}

func probeTargetProject(
	ctx context.Context,
	client *gitlabx.Client,
	p *TokenProfile,
	target string,
) ([]Capability, *ProjectAccess) {
	projectEndpoint := "/api/v4/projects/" + url.PathEscape(target)
	result := apiGet(ctx, client, projectEndpoint)
	projectCapability := capabilityFromHTTP(probeSpec{
		name: "Read target project", category: "target", endpoint: projectEndpoint,
	}, result)
	caps := []Capability{projectCapability}
	if result.Status != http.StatusOK || result.Err != nil {
		return caps, nil
	}
	var project targetProjectResponse
	if err := json.Unmarshal(result.Body, &project); err != nil {
		caps[0] = newCapability("Read target project", "target", projectEndpoint, http.MethodGet,
			StatusUnknown, "low", []string{"target project response could not be decoded"}, "")
		return caps, nil
	}
	accessLevel := project.Permissions.accessLevel()
	if p.IsAdmin {
		accessLevel = 50
	}
	projectAccess := &ProjectAccess{
		ID: project.ID, Path: project.Path, DefaultBranch: project.DefaultBranch,
		AccessLevel: accessLevel, AccessLevelName: accessLevelName(accessLevel),
	}
	if projectAccess.Path == "" {
		projectAccess.Path = target
	}

	pid := url.PathEscape(fmt.Sprintf("%d", project.ID))
	repoEndpoint := fmt.Sprintf("/api/v4/projects/%s/repository/tree?per_page=1", pid)
	repoResult := apiGet(ctx, client, repoEndpoint)
	caps = append(caps, capabilityFromHTTP(probeSpec{
		name: "Read target repository", category: "target", endpoint: repoEndpoint,
	}, repoResult))
	jobsEndpoint := fmt.Sprintf("/api/v4/projects/%s/jobs?per_page=1", pid)
	caps = append(caps, capabilityFromHTTP(probeSpec{
		name: "Read target jobs", category: "target", endpoint: jobsEndpoint,
	}, apiGet(ctx, client, jobsEndpoint)))

	projectSummary := accessSummary{Known: true, Highest: accessLevel}
	pushRepo := inferScopedCapability("Push target repository", "target", p,
		[]string{"api", "write_repository"}, 30, projectSummary)
	caps = append(caps, pushRepo)
	caps = append(caps, inferDefaultBranchPush(ctx, client, p, project, accessLevel, pushRepo))
	caps = append(caps,
		inferScopedCapability("Manage target project", "target", p, []string{"api"}, 40, projectSummary),
		inferScopedCapability("Create target runners", "target", p,
			[]string{"api", "create_runner"}, 40, projectSummary),
		inferScopedCapability("Manage target runners", "target", p,
			[]string{"api", "manage_runner"}, 40, projectSummary),
	)
	return caps, projectAccess
}

type branchAccessLevel struct {
	AccessLevel *int   `json:"access_level"`
	UserID      *int64 `json:"user_id"`
	GroupID     *int64 `json:"group_id"`
}

func inferDefaultBranchPush(
	ctx context.Context,
	client *gitlabx.Client,
	p *TokenProfile,
	project targetProjectResponse,
	accessLevel int,
	pushRepo Capability,
) Capability {
	const name = "Push target default branch"
	if pushRepo.Status == StatusDenied || pushRepo.Status == StatusUnknown {
		return newCapability(name, "target", "", "inference", pushRepo.Status, pushRepo.Confidence,
			append([]string{"repository push prerequisite not established"}, pushRepo.Evidence...), "")
	}
	if strings.TrimSpace(project.DefaultBranch) == "" {
		return newCapability(name, "target", "", "inference", StatusUnknown, "low",
			[]string{"target project has no default branch"}, "")
	}
	endpoint := fmt.Sprintf("/api/v4/projects/%d/protected_branches/%s",
		project.ID, url.PathEscape(project.DefaultBranch))
	result := apiGet(ctx, client, endpoint)
	if result.Err != nil {
		return newCapability(name, "target", endpoint, http.MethodGet, StatusUnknown, "low",
			[]string{"protected branch request failed"}, "")
	}
	if result.Status == http.StatusNotFound {
		return newCapability(name, "target", endpoint, http.MethodGet, StatusInferred, "high",
			[]string{"repository push scope and Developer access observed", "default branch is not protected"}, "")
	}
	if result.Status != http.StatusOK {
		status, confidence := classifyHTTPResult(result)
		return newCapability(name, "target", endpoint, http.MethodGet, status, confidence,
			[]string{fmt.Sprintf("protected branch query returned HTTP %d", result.Status)}, "")
	}
	var branch struct {
		PushAccessLevels []branchAccessLevel `json:"push_access_levels"`
	}
	if err := json.Unmarshal(result.Body, &branch); err != nil {
		return newCapability(name, "target", endpoint, http.MethodGet, StatusUnknown, "low",
			[]string{"protected branch response could not be decoded"}, "")
	}
	allowed, conclusive := canPushProtectedBranch(branch.PushAccessLevels, p.UserID, accessLevel)
	evidence := []string{fmt.Sprintf("default branch %q is protected", project.DefaultBranch),
		fmt.Sprintf("target project access: %s (%d)", accessLevelName(accessLevel), accessLevel)}
	if allowed {
		return newCapability(name, "target", endpoint, http.MethodGet, StatusInferred, "high", evidence, "")
	}
	if conclusive {
		return newCapability(name, "target", endpoint, http.MethodGet, StatusDenied, "high", evidence, "")
	}
	evidence = append(evidence, "group-specific push grants could not be resolved without mutation")
	return newCapability(name, "target", endpoint, http.MethodGet, StatusUnknown, "low", evidence, "")
}

func canPushProtectedBranch(levels []branchAccessLevel, userID int64, accessLevel int) (bool, bool) {
	conclusive := true
	for _, level := range levels {
		if level.UserID != nil && *level.UserID == userID {
			return true, true
		}
		if level.AccessLevel != nil && *level.AccessLevel > 0 && accessLevel >= *level.AccessLevel {
			return true, true
		}
		if level.GroupID != nil {
			conclusive = false
		}
	}
	return false, conclusive
}

func firstMatchingScope(actual, accepted []string) string {
	for _, scope := range accepted {
		if slices.Contains(actual, scope) {
			return scope
		}
	}
	return ""
}

func accessLevelName(level int) string {
	switch {
	case level >= 50:
		return "Owner/Admin"
	case level >= 40:
		return "Maintainer"
	case level >= 30:
		return "Developer"
	case level >= 25:
		return "Security Manager"
	case level >= 20:
		return "Reporter"
	case level >= 15:
		return "Planner"
	case level >= 10:
		return "Guest"
	case level >= 5:
		return "Minimal Access"
	default:
		return "No Access"
	}
}

func newCapability(
	name string,
	category string,
	endpoint string,
	method string,
	status CapabilityStatus,
	confidence string,
	evidence []string,
	detail string,
) Capability {
	return Capability{
		Name: name, Category: category, Endpoint: endpoint, Method: method,
		Accessible: status == StatusConfirmed || status == StatusInferred,
		Status:     status, Confidence: confidence, Evidence: evidence, Detail: detail,
	}
}

func countDetail(label string) func([]byte) string {
	return func(body []byte) string {
		var arr []json.RawMessage
		if json.Unmarshal(body, &arr) == nil {
			if len(arr) > 0 {
				return fmt.Sprintf("%s found", label)
			}
			return fmt.Sprintf("no %s", label)
		}
		return "accessible"
	}
}

type apiResult struct {
	Body   []byte
	Status int
	Err    error
}

func apiGet(ctx context.Context, client *gitlabx.Client, relPath string) apiResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.APIURL(relPath), nil)
	if err != nil {
		return apiResult{Err: err}
	}
	if token := client.Token(); token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.HTTPClient().Do(req) //nolint:gosec // base URL is validated by gitlabx.New
	if err != nil {
		return apiResult{Err: err}
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxProbeResponseBytes))
	return apiResult{Body: body, Status: resp.StatusCode, Err: readErr}
}
