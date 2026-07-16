package pivot

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// Credential represents a harvested GitLab token with metadata.
type Credential struct {
	Token           string // in-memory only, never persisted raw
	TokenHash       string // SHA256 for dedup/storage
	TokenType       string // "pat", "deploy_token", "project_access_token", "ci_job_token", "runner_token", "unknown"
	SourceKey       string // env var name (e.g. "GITLAB_TOKEN")
	SourceProjectID int64
	SourcePipeline  int64
	Depth           int
	UserID          int64
	Username        string
	Scopes          []string
	IsValid         bool
	GitLabURL       string
	AccessLevel     int // GitLab access level (0=none, 30=developer, 40=maintainer, 50=owner)
}

// tokenNamePatterns are env var names that likely contain GitLab tokens.
var tokenNamePatterns = []string{
	"GITLAB_TOKEN",
	"PRIVATE_TOKEN",
	"CI_JOB_TOKEN",
	"GL_TOKEN",
	"DEPLOY_TOKEN",
}

// tokenNameSuffixes are env var suffixes that likely contain GitLab tokens.
var tokenNameSuffixes = []string{
	"_ACCESS_TOKEN",
	"_PAT",
	"_DEPLOY_KEY",
}

// tokenValuePrefixes are value prefixes indicating a GitLab token.
var tokenValuePrefixes = []string{
	"glpat-",
	"gldt-",
	"glcbt-",
	"glrt-",
}

// skipKeyPrefixes are env var names to skip (short-lived JWTs).
var skipKeyPrefixes = []string{
	"CI_JOB_JWT",
}

// ExtractTokens scans environment variables for GitLab token patterns.
// Returns deduplicated credentials (by token value).
func ExtractTokens(envVars map[string]string) []Credential {
	seen := make(map[string]struct{})
	var creds []Credential

	for key, value := range envVars {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if shouldSkipKey(key) {
			continue
		}
		if !isTokenCandidate(key, value) {
			continue
		}
		hash := hashToken(value)
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		creds = append(creds, Credential{
			Token:     value,
			TokenHash: hash,
			TokenType: classifyTokenType(value),
			SourceKey: key,
		})
	}
	return creds
}

func shouldSkipKey(key string) bool {
	for _, prefix := range skipKeyPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func isTokenCandidate(key, value string) bool {
	upper := strings.ToUpper(key)
	if slices.Contains(tokenNamePatterns, upper) {
		return true
	}
	for _, suffix := range tokenNameSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	for _, prefix := range tokenValuePrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func classifyTokenType(token string) string {
	switch {
	case strings.HasPrefix(token, "glpat-"):
		return "pat"
	case strings.HasPrefix(token, "gldt-"):
		return "deploy_token"
	case strings.HasPrefix(token, "glcbt-"):
		return "project_access_token"
	case strings.HasPrefix(token, "glrt-"):
		return "runner_token"
	default:
		return "unknown"
	}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// ValidateToken checks if a token is valid by pinging the GitLab API.
// Returns a Credential with IsValid set and user info populated.
// Optional gitlabx.Option values are passed through to the client (e.g. proxy, TLS).
func ValidateToken(ctx context.Context, baseURL, token string, opts ...gitlabx.Option) (*Credential, error) {
	cl, err := gitlabx.New(baseURL, token, opts...)
	if err != nil {
		return &Credential{
			Token:     token,
			TokenHash: hashToken(token),
			TokenType: classifyTokenType(token),
			IsValid:   false,
			GitLabURL: baseURL,
		}, nil
	}
	u, _, err := cl.Ping(ctx)
	if err != nil {
		return &Credential{
			Token:     token,
			TokenHash: hashToken(token),
			TokenType: classifyTokenType(token),
			IsValid:   false,
			GitLabURL: baseURL,
		}, nil
	}
	accessLevel := 0
	if u.IsAdmin {
		accessLevel = 50
	}
	return &Credential{
		Token:       token,
		TokenHash:   hashToken(token),
		TokenType:   classifyTokenType(token),
		IsValid:     true,
		UserID:      u.ID,
		Username:    u.Username,
		GitLabURL:   baseURL,
		AccessLevel: accessLevel,
	}, nil
}

// visitKey tracks which (token, project) pairs have been processed.
type visitKey struct {
	tokenHash string
	projectID int64
}

// SortByAccessLevel sorts credentials in descending order of access level
// (admin > owner > maintainer > developer) for BFS queue prioritization.
func SortByAccessLevel(creds []*Credential) {
	slices.SortStableFunc(creds, func(a, b *Credential) int {
		return b.AccessLevel - a.AccessLevel
	})
}

// CredentialStore provides thread-safe credential tracking with visit dedup.
type CredentialStore struct {
	mu              sync.RWMutex
	creds           map[string]*Credential // tokenHash → Credential
	visited         map[visitKey]struct{}
	ProjectsByToken map[string][]int64 // tokenHash → project IDs where token was found
}

// NewCredentialStore creates an empty credential store.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		creds:           make(map[string]*Credential),
		visited:         make(map[visitKey]struct{}),
		ProjectsByToken: make(map[string][]int64),
	}
}

// Add registers a credential. No-op if token hash already known.
func (s *CredentialStore) Add(c *Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.creds[c.TokenHash]; !ok {
		s.creds[c.TokenHash] = c
	}
}

// Has returns true if a token hash is already stored.
func (s *CredentialStore) Has(tokenHash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.creds[tokenHash]
	return ok
}

// Len returns the number of stored credentials.
func (s *CredentialStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds)
}

// All returns a snapshot of all stored credentials.
func (s *CredentialStore) All() []*Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Credential, 0, len(s.creds))
	for _, c := range s.creds {
		out = append(out, c)
	}
	return out
}

// MarkVisited records that a (token, project) pair has been processed.
func (s *CredentialStore) MarkVisited(tokenHash string, projectID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.visited[visitKey{tokenHash, projectID}] = struct{}{}
}

// IsVisited returns true if a (token, project) pair has been processed.
func (s *CredentialStore) IsVisited(tokenHash string, projectID int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.visited[visitKey{tokenHash, projectID}]
	return ok
}

// RecordTokenProject records that a token was found in a specific project.
func (s *CredentialStore) RecordTokenProject(tokenHash string, projectID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.ProjectsByToken[tokenHash], projectID) {
		return
	}
	s.ProjectsByToken[tokenHash] = append(s.ProjectsByToken[tokenHash], projectID)
}

// ReusedTokens returns tokens found in more than one project.
func (s *CredentialStore) ReusedTokens() map[string][]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]int64)
	for hash, pids := range s.ProjectsByToken {
		if len(pids) > 1 {
			out[hash] = pids
		}
	}
	return out
}
