package store

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestOpen_InMemory(t *testing.T) {
	st := openTestStore(t)

	// Verify all 4 tables exist by checking the migrator.
	m := st.db.Migrator()
	for _, table := range []string{"scan_sessions", "search_results", "enumerate_results", "findings"} {
		if !m.HasTable(table) {
			t.Errorf("expected table %q to exist", table)
		}
	}
}

func TestOpen_InvalidPath(t *testing.T) {
	_, err := Open("/nonexistent/dir/that/should/fail/db.sqlite3")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestCreateSession(t *testing.T) {
	st := openTestStore(t)
	now := time.Now()
	s := &ScanSession{
		GitLabURL:   "https://gitlab.com",
		StartedAt:   now,
		Status:      "running",
		SearchTotal: 5,
	}
	if err := st.CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if s.ID == 0 {
		t.Fatal("expected non-zero session ID")
	}
	if s.GitLabURL != "https://gitlab.com" {
		t.Errorf("GitLabURL = %q, want %q", s.GitLabURL, "https://gitlab.com")
	}
	if s.SearchTotal != 5 {
		t.Errorf("SearchTotal = %d, want 5", s.SearchTotal)
	}
}

func TestUpdateSession(t *testing.T) {
	st := openTestStore(t)
	s := &ScanSession{
		GitLabURL: "https://gitlab.com",
		StartedAt: time.Now(),
		Status:    "running",
	}
	if err := st.CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	now := time.Now()
	s.Status = "completed"
	s.FinishedAt = &now
	if err := st.UpdateSession(s); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	got, err := st.GetSession(s.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != "completed" {
		t.Errorf("Status = %q, want %q", got.Status, "completed")
	}
	if got.FinishedAt == nil {
		t.Error("FinishedAt should not be nil")
	}
}

func TestSaveSearchResults(t *testing.T) {
	st := openTestStore(t)
	s := &ScanSession{
		GitLabURL: "https://gitlab.com",
		StartedAt: time.Now(),
		Status:    "completed",
	}
	if err := st.CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	results := []SearchResult{
		{GitLabProjectID: 100, PathWithNamespace: "group/proj-a", WebURL: "https://gitlab.com/group/proj-a", Visibility: "public", DefaultBranch: "main"},
		{GitLabProjectID: 200, PathWithNamespace: "group/proj-b", WebURL: "https://gitlab.com/group/proj-b", Visibility: "private", DefaultBranch: "master"},
		{GitLabProjectID: 300, PathWithNamespace: "group/proj-c", WebURL: "https://gitlab.com/group/proj-c", Visibility: "internal", DefaultBranch: "main"},
	}
	if err := st.SaveSearchResults(s.ID, results); err != nil {
		t.Fatalf("SaveSearchResults: %v", err)
	}

	got, err := st.GetSession(s.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.SearchResults) != 3 {
		t.Fatalf("SearchResults count = %d, want 3", len(got.SearchResults))
	}
	// Verify SessionID was set.
	for _, r := range got.SearchResults {
		if r.SessionID != s.ID {
			t.Errorf("SearchResult.SessionID = %d, want %d", r.SessionID, s.ID)
		}
	}
}

func TestSaveEnumerateResults_WithFindings(t *testing.T) {
	st := openTestStore(t)
	s := &ScanSession{
		GitLabURL: "https://gitlab.com",
		StartedAt: time.Now(),
		Status:    "completed",
	}
	if err := st.CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	results := []EnumerateResult{
		{
			GitLabProjectID:   100,
			PathWithNamespace: "group/proj-a",
			HasCIPipeline:     true,
			FindingsCount:     2,
			Findings: []Finding{
				{FindingID: "INCLUDE_REMOTE", Severity: "HIGH", Title: "Remote include"},
				{FindingID: "PLAINTEXT_SECRET", Severity: "HIGH", Title: "Plaintext secret"},
			},
		},
		{
			GitLabProjectID:   200,
			PathWithNamespace: "group/proj-b",
			HasCIPipeline:     true,
			FindingsCount:     1,
			Findings: []Finding{
				{FindingID: "VARIABLE_INJECTION", Severity: "MEDIUM", Title: "Variable injection"},
			},
		},
	}
	if err := st.SaveEnumerateResults(s.ID, results); err != nil {
		t.Fatalf("SaveEnumerateResults: %v", err)
	}

	got, err := st.GetSession(s.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.EnumerateResults) != 2 {
		t.Fatalf("EnumerateResults count = %d, want 2", len(got.EnumerateResults))
	}

	totalFindings := 0
	for _, r := range got.EnumerateResults {
		totalFindings += len(r.Findings)
		if r.SessionID != s.ID {
			t.Errorf("EnumerateResult.SessionID = %d, want %d", r.SessionID, s.ID)
		}
	}
	if totalFindings != 3 {
		t.Errorf("total findings = %d, want 3", totalFindings)
	}
}

func TestSaveEnumerateResults_NoFindings(t *testing.T) {
	st := openTestStore(t)
	s := &ScanSession{
		GitLabURL: "https://gitlab.com",
		StartedAt: time.Now(),
		Status:    "completed",
	}
	if err := st.CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	results := []EnumerateResult{
		{
			GitLabProjectID:   100,
			PathWithNamespace: "group/proj-a",
			HasCIPipeline:     false,
			FindingsCount:     0,
		},
	}
	if err := st.SaveEnumerateResults(s.ID, results); err != nil {
		t.Fatalf("SaveEnumerateResults: %v", err)
	}

	got, err := st.GetSession(s.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.EnumerateResults) != 1 {
		t.Fatalf("EnumerateResults count = %d, want 1", len(got.EnumerateResults))
	}
	if len(got.EnumerateResults[0].Findings) != 0 {
		t.Errorf("Findings count = %d, want 0", len(got.EnumerateResults[0].Findings))
	}
}

func TestGetSession_NotFound(t *testing.T) {
	st := openTestStore(t)
	_, err := st.GetSession(999)
	if err == nil {
		t.Fatal("expected error for non-existent session")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("error = %v, want gorm.ErrRecordNotFound", err)
	}
}

func TestListSessions_Ordering(t *testing.T) {
	st := openTestStore(t)
	for i := range 5 {
		s := &ScanSession{
			GitLabURL:   "https://gitlab.com",
			StartedAt:   time.Now(),
			Status:      "completed",
			SearchTotal: i + 1,
		}
		if err := st.CreateSession(s); err != nil {
			t.Fatalf("CreateSession[%d]: %v", i, err)
		}
	}

	all, err := st.ListSessions(0)
	if err != nil {
		t.Fatalf("ListSessions(0): %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("ListSessions(0) count = %d, want 5", len(all))
	}
	// Newest-first: last created has highest ID.
	if all[0].ID < all[4].ID {
		t.Error("expected newest-first ordering")
	}

	limited, err := st.ListSessions(2)
	if err != nil {
		t.Fatalf("ListSessions(2): %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("ListSessions(2) count = %d, want 2", len(limited))
	}
}

func TestListSessions_Empty(t *testing.T) {
	st := openTestStore(t)
	sessions, err := st.ListSessions(0)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions == nil {
		t.Error("expected non-nil empty slice")
	}
	if len(sessions) != 0 {
		t.Errorf("count = %d, want 0", len(sessions))
	}
}

func TestClose(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
