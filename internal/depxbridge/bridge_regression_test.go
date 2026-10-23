package depxbridge

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const regressionPackageLock = `{"lockfileVersion":3,"packages":{"node_modules/safe-fixture":{"version":"1.2.3"}}}`

func regressionAuditor(t *testing.T) *Auditor {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		writer := gzip.NewWriter(w)
		if err := json.NewEncoder(writer).Encode(map[string]any{
			"schema_version": "1",
			"generated_at":   time.Now().UTC().Format(time.RFC3339),
			"packages":       []any{},
		}); err != nil {
			t.Errorf("encode inventory: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Errorf("close inventory: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("DEPX_SOURCE_URL", server.URL+"/inventory.json.gz")
	auditor, err := New(Options{CacheDir: t.TempDir(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auditor.Close)
	return auditor
}

func TestAuditorDirectoryDiscovery(t *testing.T) {
	auditor := regressionAuditor(t)
	for _, mode := range []string{"default", "portable walk"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "portable walk" {
				t.Setenv("PATH", t.TempDir()) // Exercise the fallback when find is unavailable.
			}
			assertDirectoryDiscovery(t, auditor)
		})
	}
}

func assertDirectoryDiscovery(t *testing.T, auditor *Auditor) {
	t.Helper()
	for _, test := range []struct {
		name    string
		path    string
		content string
	}{
		{"cargo", "Cargo.lock", "version = 3\n[[package]]\nname = \"safe-fixture\"\nversion = \"1.2.3\"\n"},
		{"pipenv", "Pipfile.lock", `{"default":{"safe-fixture":{"version":"==1.2.3"}}}`},
		{"bundler", "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    safe-fixture (1.2.3)\n"},
		{"newline directory", "line\nbreak/package-lock.json", regressionPackageLock},
		{"sbom", "nested/bom.json", `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"safe-fixture","version":"1.2.3","purl":"pkg:npm/safe-fixture@1.2.3"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "newline directory" && runtime.GOOS == "windows" {
				t.Skip("Windows disallows newline characters in filenames")
			}
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(test.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := auditor.Audit(t.Context(), []string{root})
			if err != nil {
				t.Fatal(err)
			}
			if result.Dependencies != 1 || len(result.Lockfiles) != 1 || result.Lockfiles[0].Path != path {
				t.Fatalf("directory audit skipped source %q: %+v", path, result)
			}
		})
	}
}

func TestAuditorSBOMRoundTrip(t *testing.T) {
	auditor := regressionAuditor(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(regressionPackageLock), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			_, data, err := auditor.AuditSBOM(t.Context(), []string{root}, format)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			path := filepath.Join(directory, "report."+format+".json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := auditor.Audit(t.Context(), []string{directory})
			if err != nil {
				t.Fatal(err)
			}
			if result.Dependencies != 1 || len(result.Lockfiles) != 1 || result.Lockfiles[0].Path != path {
				t.Fatalf("export/import lost dependency metadata: %+v", result)
			}
		})
	}
}

func TestAuditorRejectsMalformedLockfile(t *testing.T) {
	auditor := regressionAuditor(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := auditor.Audit(t.Context(), []string{root}); err == nil {
		t.Fatalf("malformed lockfile reported a successful scan: %+v", result)
	}
}

func TestAuditorExportsEmptySBOM(t *testing.T) {
	auditor := regressionAuditor(t)
	for _, withLockfile := range []bool{false, true} {
		root := t.TempDir()
		if withLockfile {
			if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, format := range []string{"cyclonedx", "spdx"} {
			result, data, err := auditor.AuditSBOM(t.Context(), []string{root}, format)
			if err != nil {
				t.Errorf("%s export (lockfile=%t): %v", format, withLockfile, err)
				continue
			}
			if result.Dependencies != 0 || !json.Valid(data) || result.SBOMPath != "" {
				t.Errorf("invalid empty %s export: %+v, %s", format, result, data)
			}
		}
	}
}

func TestNilAuditorSBOM(t *testing.T) {
	var auditor *Auditor
	if _, _, err := auditor.AuditSBOM(context.Background(), nil, "cyclonedx"); err == nil {
		t.Fatal("nil Auditor.AuditSBOM returned nil error")
	}
}
