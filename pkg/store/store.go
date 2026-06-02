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
		&SecretScanResult{},
		&SecretFinding{},
		&PivotSession{},
		&HarvestedCredential{},
		&ExfiltratedSecret{},
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
