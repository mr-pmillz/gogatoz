package cmd

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

func TestPersistSearchResults_NilStore(t *testing.T) {
	old := cliStore
	cliStore = nil
	defer func() { cliStore = old }()
	// Should not panic
	persistSearchResults([]map[string]any{{"id": int64(1), "path_with_namespace": "a/b"}}, "https://gitlab.com")
}

func TestPersistSearchResults_WithStore(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	old := cliStore
	cliStore = st
	defer func() { cliStore = old }()

	results := []map[string]any{
		{
			"id":                  int64(42),
			"path_with_namespace": "org/repo",
			"web_url":             "https://gitlab.com/org/repo",
			"visibility":          "public",
			"default_branch":      "main",
			"star_count":          int64(10),
		},
		{
			"id":                  int64(43),
			"path_with_namespace": "org/repo2",
			"web_url":             "https://gitlab.com/org/repo2",
			"visibility":          "internal",
			"default_branch":      "develop",
			"star_count":          int64(5),
		},
	}
	persistSearchResults(results, "https://gitlab.com")

	sessions, err := st.ListSessions(1)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].SearchTotal != 2 {
		t.Fatalf("expected SearchTotal=2, got %d", sessions[0].SearchTotal)
	}

	sess, err := st.GetSession(sessions[0].ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if len(sess.SearchResults) != 2 {
		t.Fatalf("expected 2 search results, got %d", len(sess.SearchResults))
	}
	if sess.SearchResults[0].StarCount != 10 {
		t.Fatalf("expected StarCount=10, got %d", sess.SearchResults[0].StarCount)
	}
}

func TestPersistEnumerateResults_NilStore(t *testing.T) {
	old := cliStore
	cliStore = nil
	defer func() { cliStore = old }()
	// Should not panic
	persistEnumerateResults([]enumerate.Result{{ProjectID: 1}}, "https://gitlab.com")
}

func TestPersistEnumerateResults_WithStore(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	old := cliStore
	cliStore = st
	defer func() { cliStore = old }()

	results := []enumerate.Result{
		{
			ProjectID:         100,
			ProjectPathWithNS: "group/proj",
			WebURL:            "https://gitlab.com/group/proj",
			DefaultBranch:     "main",
			StarCount:         25,
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "INCLUDE_REMOTE", Severity: analyze.SeverityHigh, Title: "Remote include"},
			},
			RunnersTotal:  3,
			RunnersOnline: 1,
		},
	}
	persistEnumerateResults(results, "https://gitlab.com")

	sessions, err := st.ListSessions(1)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].EnumTotal != 1 {
		t.Fatalf("expected EnumTotal=1, got %d", sessions[0].EnumTotal)
	}
	if sessions[0].EnumFindings != 1 {
		t.Fatalf("expected EnumFindings=1, got %d", sessions[0].EnumFindings)
	}

	sess, err := st.GetSession(sessions[0].ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if len(sess.EnumerateResults) != 1 {
		t.Fatalf("expected 1 enumerate result, got %d", len(sess.EnumerateResults))
	}
	er := sess.EnumerateResults[0]
	if er.StarCount != 25 {
		t.Fatalf("expected StarCount=25, got %d", er.StarCount)
	}
	if er.RunnersTotal != 3 {
		t.Fatalf("expected RunnersTotal=3, got %d", er.RunnersTotal)
	}
	if len(er.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(er.Findings))
	}
	if er.Findings[0].FindingID != "INCLUDE_REMOTE" {
		t.Fatalf("expected finding ID INCLUDE_REMOTE, got %q", er.Findings[0].FindingID)
	}
}

func TestToInt64(t *testing.T) {
	tests := []struct {
		in   any
		want int64
	}{
		{int64(42), 42},
		{int(10), 10},
		{float64(99.0), 99},
		{"not a number", 0},
		{nil, 0},
	}
	for _, tt := range tests {
		got := toInt64(tt.in)
		if got != tt.want {
			t.Errorf("toInt64(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
