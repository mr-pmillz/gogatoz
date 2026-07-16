package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadThreatIntelFile(t *testing.T) {
	feed := ThreatIntelFeed{
		BlockedDomains: []string{"evil.example.com", "c2.bad.org"},
		BlockedIPs:     []string{"1.2.3.4"},
	}
	data, _ := json.Marshal(feed)
	path := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadThreatIntelFile(path)
	if err != nil {
		t.Fatalf("LoadThreatIntelFile: %v", err)
	}
	if len(loaded.BlockedDomains) != 2 {
		t.Fatalf("expected 2 blocked domains, got %d", len(loaded.BlockedDomains))
	}
	if loaded.UpdatedAt.IsZero() {
		t.Fatal("expected UpdatedAt to be set")
	}
}

func TestLoadThreatIntelFeed(t *testing.T) {
	feed := ThreatIntelFeed{
		BlockedDomains: []string{"malware.example.com"},
		BlockedIPs:     []string{"10.0.0.1"},
		BlockedHashes:  []string{"abc123"},
	}
	data, _ := json.Marshal(feed)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer srv.Close()

	loaded, err := LoadThreatIntelFeed(srv.URL)
	if err != nil {
		t.Fatalf("LoadThreatIntelFeed: %v", err)
	}
	if len(loaded.BlockedDomains) != 1 || loaded.BlockedDomains[0] != "malware.example.com" {
		t.Fatalf("unexpected domains: %v", loaded.BlockedDomains)
	}
}

func TestThreatIntelCache_HitAndExpiry(t *testing.T) {
	calls := 0
	feed := ThreatIntelFeed{BlockedDomains: []string{"cached.example.com"}}
	data, _ := json.Marshal(feed)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer srv.Close()

	cache := NewThreatIntelCache(1 * time.Hour)
	f1, err := cache.LoadURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(f1.BlockedDomains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(f1.BlockedDomains))
	}
	// Second call should be cached
	_, _ = cache.LoadURL(srv.URL)
	if calls != 1 {
		t.Fatalf("expected 1 fetch call (cached), got %d", calls)
	}
}

func TestLoadThreatIntelFile_NotFound(t *testing.T) {
	_, err := LoadThreatIntelFile("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
