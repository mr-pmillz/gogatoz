package depxbridge

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditor_AuditUsesDepxNativeService(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	inventory := map[string]any{
		"schema_version": "1",
		"generated_at":   now.Format(time.RFC3339),
		"source":         "gogatoz-test",
		"packages": []map[string]any{
			{
				"ecosystem":         "npm",
				"name":              "gogatoz-synthetic-malicious",
				"ids":               []string{"MAL-2099-GOGATOZ-TEST"},
				"all_versions":      true,
				"summary":           "Synthetic malicious-package record for GoGatoZ tests",
				"published_at":      now.Format(time.RFC3339),
				"modified_at":       now.Format(time.RFC3339),
				"imported_at":       now.Format(time.RFC3339),
				"affected_versions": []string{"1.2.3"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		gz := gzip.NewWriter(w)
		if err := json.NewEncoder(gz).Encode(inventory); err != nil {
			t.Errorf("encode inventory: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Errorf("close inventory gzip stream: %v", err)
		}
	}))
	defer srv.Close()
	t.Setenv("DEPX_SOURCE_URL", srv.URL+"/export")

	projectDir := t.TempDir()
	lockfile := filepath.Join(projectDir, "package-lock.json")
	lockJSON := `{
  "name": "gogatoz-safe-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "gogatoz-safe-fixture",
      "version": "1.0.0",
      "dependencies": {"gogatoz-synthetic-malicious": "1.2.3"}
    },
    "node_modules/gogatoz-synthetic-malicious": {
      "version": "1.2.3",
      "resolved": "https://registry.invalid/gogatoz-synthetic-malicious/-/gogatoz-synthetic-malicious-1.2.3.tgz",
      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}`
	if err := os.WriteFile(lockfile, []byte(lockJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	auditor, err := New(Options{
		CacheDir: t.TempDir(),
		Timeout:  10 * time.Second,
		Version:  "gogatoz-test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer auditor.Close()

	result, err := auditor.Audit(context.Background(), []string{projectDir})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if result.Dependencies != 1 {
		t.Fatalf("Dependencies = %d, want 1", result.Dependencies)
	}
	if result.Summary.Malicious != 1 {
		t.Fatalf("Summary.Malicious = %d, want 1", result.Summary.Malicious)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Name != "gogatoz-synthetic-malicious" || finding.Version != "1.2.3" {
		t.Fatalf("finding package = %s@%s", finding.Name, finding.Version)
	}
	if len(finding.IDs) != 1 || finding.IDs[0] != "MAL-2099-GOGATOZ-TEST" {
		t.Fatalf("finding IDs = %v", finding.IDs)
	}

	assertNativeSBOMExports(t, auditor, projectDir)
}

func assertNativeSBOMExports(t *testing.T, auditor *Auditor, projectDir string) {
	t.Helper()
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run("native "+format+" export", func(t *testing.T) {
			exportedResult, sbom, exportErr := auditor.AuditSBOM(context.Background(), []string{projectDir}, format)
			if exportErr != nil {
				t.Fatalf("AuditSBOM: %v", exportErr)
			}
			if exportedResult.Dependencies != 1 || len(exportedResult.Findings) != 1 {
				t.Fatalf("exported result = %+v", exportedResult)
			}
			var document map[string]any
			if err := json.Unmarshal(sbom, &document); err != nil {
				t.Fatalf("decode %s SBOM: %v", format, err)
			}
			if format == "cyclonedx" && document["bomFormat"] != "CycloneDX" {
				t.Fatalf("CycloneDX document = %+v", document)
			}
			if format == "spdx" && document["spdxVersion"] != "SPDX-2.3" {
				t.Fatalf("SPDX document = %+v", document)
			}
		})
	}
}
