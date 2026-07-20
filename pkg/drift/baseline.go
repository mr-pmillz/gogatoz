package drift

import (
	"crypto/sha256"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// ConfigBaseline stores a snapshot of a project's CI config for drift comparison.
type ConfigBaseline struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	ProjectID   int64     `json:"project_id"`
	ProjectPath string    `json:"project_path"`
	Ref         string    `json:"ref"`
	ConfigHash  string    `json:"config_hash"`
	ConfigYAML  string    `gorm:"type:text" json:"config_yaml"`
	SavedAt     time.Time `json:"saved_at"`
}

// SaveBaseline upserts a CI config baseline for the given project.
func SaveBaseline(db *gorm.DB, projectID int64, projectPath, ref, yaml string) error {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(yaml)))
	baseline := ConfigBaseline{
		ProjectID:   projectID,
		ProjectPath: projectPath,
		Ref:         ref,
		ConfigHash:  hash,
		ConfigYAML:  yaml,
		SavedAt:     time.Now(),
	}
	return db.Where("project_id = ?", projectID).
		Assign(baseline).
		FirstOrCreate(&baseline).Error
}

// LoadBaseline retrieves the stored baseline for a project.
func LoadBaseline(db *gorm.DB, projectID int64) (*ConfigBaseline, error) {
	var b ConfigBaseline
	err := db.Where("project_id = ?", projectID).First(&b).Error
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// HasChanged checks whether the current YAML differs from the stored baseline.
func HasChanged(db *gorm.DB, projectID int64, currentYAML string) (bool, error) {
	b, err := LoadBaseline(db, projectID)
	if err != nil {
		return true, err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(currentYAML)))
	return hash != b.ConfigHash, nil
}
