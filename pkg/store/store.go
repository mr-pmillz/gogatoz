package store

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store wraps a GORM database handle for scan result persistence.
type Store struct {
	db *gorm.DB
}

// Open creates or opens a SQLite database at dbPath, enables WAL mode,
// and runs AutoMigrate for all model types. Use ":memory:" for tests.
func Open(dbPath string) (*Store, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("raw db: %w", err)
	}
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("wal mode: %w", err)
	}

	if err := db.AutoMigrate(
		&ScanSession{},
		&SearchResult{},
		&EnumerateResult{},
		&Finding{},
		&AttackResult{},
		&AttackExfilSecret{},
		&SecretScanResult{},
		&SecretFinding{},
		&PivotSession{},
		&HarvestedCredential{},
		&ExfiltratedSecret{},
		&GraphNode{},
		&GraphEdge{},
	); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// CreateSession inserts a new scan session.
func (s *Store) CreateSession(session *ScanSession) error {
	return s.db.Create(session).Error
}

// UpdateSession saves changes to an existing session.
func (s *Store) UpdateSession(session *ScanSession) error {
	return s.db.Save(session).Error
}

// SaveSearchResults bulk-inserts search results for the given session.
func (s *Store) SaveSearchResults(sessionID uint, results []SearchResult) error {
	for i := range results {
		results[i].SessionID = sessionID
	}
	return s.db.CreateInBatches(results, 100).Error
}

// SaveEnumerateResults bulk-inserts enumerate results with their nested
// findings for the given session.
func (s *Store) SaveEnumerateResults(sessionID uint, results []EnumerateResult) error {
	for i := range results {
		results[i].SessionID = sessionID
	}
	return s.db.CreateInBatches(results, 50).Error
}

// SaveAttackResults bulk-inserts attack results for the given session.
func (s *Store) SaveAttackResults(sessionID uint, results []AttackResult) error {
	for i := range results {
		results[i].SessionID = sessionID
	}
	return s.db.CreateInBatches(results, 50).Error
}

// SaveAttackResult inserts a single attack result, populating its ID on success.
func (s *Store) SaveAttackResult(sessionID uint, result *AttackResult) error {
	result.SessionID = sessionID
	return s.db.Create(result).Error
}

// SaveAttackExfilSecrets bulk-inserts decrypted exfil secrets linked to an attack result.
func (s *Store) SaveAttackExfilSecrets(attackResultID uint, secrets []AttackExfilSecret) error {
	for i := range secrets {
		secrets[i].AttackResultID = attackResultID
	}
	return s.db.CreateInBatches(secrets, 100).Error
}

// SaveSecretScanResults bulk-inserts secret scan results with their nested
// findings for the given session.
func (s *Store) SaveSecretScanResults(sessionID uint, results []SecretScanResult) error {
	for i := range results {
		results[i].SessionID = sessionID
	}
	return s.db.CreateInBatches(results, 50).Error
}

// GetSession retrieves a session by ID with all preloaded relationships.
func (s *Store) GetSession(id uint) (*ScanSession, error) {
	var session ScanSession
	err := s.db.
		Preload("SearchResults").
		Preload("EnumerateResults.Findings").
		Preload("AttackResults").
		Preload("SecretScanResults.SecretFindings").
		First(&session, id).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// ListSessions returns recent sessions ordered newest-first.
// Pass limit <= 0 for unlimited.
func (s *Store) ListSessions(limit int) ([]ScanSession, error) {
	var sessions []ScanSession
	q := s.db.Order("created_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	return sessions, q.Find(&sessions).Error
}

// SavePivotSession inserts or updates a pivot session.
func (s *Store) SavePivotSession(session *PivotSession) error {
	return s.db.Save(session).Error
}

// SaveHarvestedCredentials bulk-inserts harvested credentials for a pivot session.
func (s *Store) SaveHarvestedCredentials(pivotSessionID uint, creds []HarvestedCredential) error {
	for i := range creds {
		creds[i].PivotSessionID = pivotSessionID
	}
	return s.db.CreateInBatches(creds, 50).Error
}

// SaveExfiltratedSecrets bulk-inserts exfiltrated secrets for a pivot session.
func (s *Store) SaveExfiltratedSecrets(pivotSessionID uint, secrets []ExfiltratedSecret) error {
	for i := range secrets {
		secrets[i].PivotSessionID = pivotSessionID
	}
	return s.db.CreateInBatches(secrets, 100).Error
}

// DB exposes the raw GORM handle for advanced queries or testing.
func (s *Store) DB() *gorm.DB { return s.db }

// ---- Query methods ----

// GetEnumerateResultsBySession returns all enumerate results for a session.
func (s *Store) GetEnumerateResultsBySession(sessionID uint) ([]EnumerateResult, error) {
	var results []EnumerateResult
	err := s.db.Where("session_id = ?", sessionID).Preload("Findings").Find(&results).Error
	return results, err
}

// GetAllEnumerateResults returns all enumerate results with findings preloaded.
func (s *Store) GetAllEnumerateResults() ([]EnumerateResult, error) {
	var results []EnumerateResult
	err := s.db.Preload("Findings").Find(&results).Error
	return results, err
}

// GetAllAttackResults returns all attack results.
func (s *Store) GetAllAttackResults() ([]AttackResult, error) {
	var results []AttackResult
	err := s.db.Find(&results).Error
	return results, err
}

// GetAttackResultsBySession returns attack results for a session.
func (s *Store) GetAttackResultsBySession(sessionID uint) ([]AttackResult, error) {
	var results []AttackResult
	err := s.db.Where("session_id = ?", sessionID).Find(&results).Error
	return results, err
}

// GetAttackExfilSecrets returns decrypted exfil secrets for an attack result.
func (s *Store) GetAttackExfilSecrets(attackResultID uint) ([]AttackExfilSecret, error) {
	var secrets []AttackExfilSecret
	err := s.db.Where("attack_result_id = ?", attackResultID).Find(&secrets).Error
	return secrets, err
}

// GetAllHarvestedCredentials returns all harvested credentials.
func (s *Store) GetAllHarvestedCredentials() ([]HarvestedCredential, error) {
	var creds []HarvestedCredential
	err := s.db.Find(&creds).Error
	return creds, err
}

// GetAllExfiltratedSecrets returns all exfiltrated secrets from pivot callbacks.
func (s *Store) GetAllExfiltratedSecrets() ([]ExfiltratedSecret, error) {
	var secrets []ExfiltratedSecret
	err := s.db.Order("source_project_path ASC, key ASC").Find(&secrets).Error
	return secrets, err
}

// SaveGraphNodes persists BloodHound graph nodes for a session.
func (s *Store) SaveGraphNodes(sessionID uint, nodes []GraphNode) error {
	for i := range nodes {
		nodes[i].SessionID = sessionID
	}
	return s.db.CreateInBatches(nodes, 100).Error
}

// SaveGraphEdges persists BloodHound graph edges for a session.
func (s *Store) SaveGraphEdges(sessionID uint, edges []GraphEdge) error {
	for i := range edges {
		edges[i].SessionID = sessionID
	}
	return s.db.CreateInBatches(edges, 100).Error
}

// GetGraphNodes returns all graph nodes for a session.
func (s *Store) GetGraphNodes(sessionID uint) ([]GraphNode, error) {
	var nodes []GraphNode
	err := s.db.Where("session_id = ?", sessionID).Find(&nodes).Error
	return nodes, err
}

// GetGraphEdges returns all graph edges for a session.
func (s *Store) GetGraphEdges(sessionID uint) ([]GraphEdge, error) {
	var edges []GraphEdge
	err := s.db.Where("session_id = ?", sessionID).Find(&edges).Error
	return edges, err
}
