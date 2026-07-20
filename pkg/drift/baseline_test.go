package drift

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&ConfigBaseline{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestSaveAndLoadBaseline(t *testing.T) {
	db := openTestDB(t)
	yaml := "stages:\n  - build\nbuild:\n  script: make"

	if err := SaveBaseline(db, 42, "group/project", "main", yaml); err != nil {
		t.Fatalf("save: %v", err)
	}

	b, err := LoadBaseline(db, 42)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.ProjectID != 42 {
		t.Errorf("project_id = %d, want 42", b.ProjectID)
	}
	if b.ConfigYAML != yaml {
		t.Errorf("yaml mismatch")
	}
	if b.ProjectPath != "group/project" {
		t.Errorf("project_path = %q, want %q", b.ProjectPath, "group/project")
	}
	if b.Ref != "main" {
		t.Errorf("ref = %q, want %q", b.Ref, "main")
	}
	if b.ConfigHash == "" {
		t.Error("expected non-empty config hash")
	}
}

func TestSaveBaseline_Upsert(t *testing.T) {
	db := openTestDB(t)

	if err := SaveBaseline(db, 1, "p", "main", "v1"); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := SaveBaseline(db, 1, "p", "main", "v2"); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	b, err := LoadBaseline(db, 1)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.ConfigYAML != "v2" {
		t.Errorf("expected upserted yaml 'v2', got %q", b.ConfigYAML)
	}
}

func TestLoadBaseline_NotFound(t *testing.T) {
	db := openTestDB(t)
	_, err := LoadBaseline(db, 999)
	if err == nil {
		t.Error("expected error for missing baseline")
	}
}

func TestHasChanged(t *testing.T) {
	db := openTestDB(t)
	yaml := "build:\n  script: make"
	if err := SaveBaseline(db, 1, "p", "main", yaml); err != nil {
		t.Fatalf("save: %v", err)
	}

	changed, err := HasChanged(db, 1, yaml)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected no change for same yaml")
	}

	changed, err = HasChanged(db, 1, yaml+" modified")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected change for modified yaml")
	}
}

func TestHasChanged_NoBaseline(t *testing.T) {
	db := openTestDB(t)
	changed, err := HasChanged(db, 999, "anything")
	if err == nil {
		t.Error("expected error when no baseline exists")
	}
	if !changed {
		t.Error("expected changed=true when no baseline exists")
	}
}
