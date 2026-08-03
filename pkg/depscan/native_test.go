package depscan

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewNativeScannerAuditsSyntheticInventory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	inventory := map[string]any{
		"schema_version": "1",
		"generated_at":   now.Format(time.RFC3339),
		"source":         "gogatoz-test",
		"packages": []map[string]any{{
			"ecosystem": "npm", "name": "gogatoz-synthetic-malicious",
			"ids": []string{"MAL-2099-GOGATOZ-TEST"}, "all_versions": true,
			"affected_versions": []string{"1.2.3"}, "severity": "critical",
			"summary":      "Synthetic malicious-package record for GoGatoZ tests",
			"published_at": now.Format(time.RFC3339),
			"modified_at":  now.Format(time.RFC3339),
			"imported_at":  now.Format(time.RFC3339),
		}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		gz := gzip.NewWriter(w)
		if err := json.NewEncoder(gz).Encode(inventory); err != nil {
			t.Errorf("encode inventory: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Errorf("close inventory: %v", err)
		}
	}))
	defer server.Close()
	t.Setenv("DEPX_SOURCE_URL", server.URL+"/inventory.json.gz")

	projectDir := t.TempDir()
	lockfile := filepath.Join(projectDir, "package-lock.json")
	lockJSON := `{
  "name": "gogatoz-safe-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"gogatoz-synthetic-malicious": "1.2.3"}},
    "node_modules/gogatoz-synthetic-malicious": {
      "version": "1.2.3",
      "resolved": "https://registry.invalid/gogatoz-synthetic-malicious-1.2.3.tgz"
    }
  }
}`
	if err := os.WriteFile(lockfile, []byte(lockJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner, err := New(Options{
		CacheDir: t.TempDir(), Timeout: 10 * time.Second, Version: "gogatoz-test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(scanner.Close)

	report, err := scanner.Scan(context.Background(), []string{projectDir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.Engine != "depx" || report.Dependencies != 1 || report.Summary.Malicious != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Lockfiles) != 1 || report.Lockfiles[0].Path != lockfile {
		t.Fatalf("lockfiles = %+v", report.Lockfiles)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != MaliciousDependencyID ||
		!strings.Contains(report.Findings[0].Evidence, "MAL-2099-GOGATOZ-TEST") {
		t.Fatalf("findings = %+v", report.Findings)
	}
}

func TestNewNativeScannerWrapsCacheInitializationError(t *testing.T) {
	cacheFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(cacheFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{CacheDir: cacheFile, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "create native depx scanner") {
		t.Fatalf("New error = %v, want wrapped cache initialization error", err)
	}
}

func TestNativeAuditorCloseIsNilSafe(t *testing.T) {
	var nilAuditor *nativeAuditor
	nilAuditor.Close()
	(&nativeAuditor{}).Close()
}
