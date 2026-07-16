package pivot

// Correlation represents a token found across multiple projects.
type Correlation struct {
	TokenHash   string  `json:"token_hash"`
	ProjectIDs  []int64 `json:"project_ids"`
	TokenType   string  `json:"token_type"`
	SharedCount int     `json:"shared_count"`
}

// CorrelateCredentials identifies tokens that appear in multiple projects,
// indicating shared secrets or credential reuse across the CI/CD surface.
func CorrelateCredentials(store *CredentialStore) []Correlation {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()

	var correlations []Correlation
	for hash, projectIDs := range store.ProjectsByToken {
		if len(projectIDs) < 2 {
			continue
		}
		tokenType := "unknown"
		if c, ok := store.creds[hash]; ok {
			tokenType = c.TokenType
		}
		displayHash := hash
		if len(hash) > 12 {
			displayHash = hash[:12] + "..."
		}
		correlations = append(correlations, Correlation{
			TokenHash:   displayHash,
			ProjectIDs:  projectIDs,
			TokenType:   tokenType,
			SharedCount: len(projectIDs),
		})
	}
	return correlations
}
