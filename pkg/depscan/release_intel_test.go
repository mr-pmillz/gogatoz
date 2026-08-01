package depscan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistryReleaseProviderParsesSupportedEcosystems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.EscapedPath() {
		case "/@scope%2Fsafe-package":
			_, _ = io.WriteString(w, `{"time":{"created":"2026-01-01T00:00:00Z","1.2.3":"2026-07-31T10:00:00Z"}}`)
		case "/pypi/safe-python/json":
			_, _ = io.WriteString(w, `{"releases":{"2.0.0":[{"upload_time_iso_8601":"2026-07-31T10:30:00Z"}]}}`)
		case "/api/v1/versions/safe-gem.json":
			_, _ = io.WriteString(w, `[{"number":"3.0.0","created_at":"2026-07-31T11:00:00Z"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GOGATOZ_NPM_REGISTRY_URL", server.URL)
	t.Setenv("GOGATOZ_PYPI_REGISTRY_URL", server.URL)
	t.Setenv("GOGATOZ_RUBYGEMS_REGISTRY_URL", server.URL)
	provider, err := newRegistryReleaseProvider(time.Second)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		ecosystem string
		name      string
		version   string
	}{
		{ecosystem: "npm", name: "@scope/safe-package", version: "1.2.3"},
		{ecosystem: "pypi", name: "safe-python", version: "2.0.0"},
		{ecosystem: "gem", name: "safe-gem", version: "3.0.0"},
	} {
		t.Run(test.ecosystem, func(t *testing.T) {
			history, historyErr := provider.ReleaseHistory(context.Background(), test.ecosystem, test.name)
			if historyErr != nil {
				t.Fatalf("ReleaseHistory: %v", historyErr)
			}
			if len(history.Versions) != 1 || history.Versions[0].Version != test.version || history.Versions[0].PublishedAt.IsZero() {
				t.Fatalf("history = %+v", history)
			}
		})
	}
}

type fakeReleaseProvider struct {
	histories map[string]ReleaseHistory
	err       error
}

func (f *fakeReleaseProvider) ReleaseHistory(_ context.Context, ecosystem, name string) (ReleaseHistory, error) {
	if f.err != nil {
		return ReleaseHistory{}, f.err
	}
	return f.histories[ecosystem+":"+name], nil
}

func TestScannerScanReleaseIntelUsesNativeDepxComponents(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	auditor := &fakeSBOMAuditor{
		fakeAuditor: fakeAuditor{result: AuditResult{Dependencies: 3}},
		sbom: []byte(`{
  "bomFormat": "CycloneDX",
  "components": [
    {"type":"library","name":"fresh-js","version":"2.0.0","purl":"pkg:npm/fresh-js@2.0.0"},
    {"type":"library","name":"quiet-python","version":"1.1.0","purl":"pkg:pypi/quiet-python@1.1.0"},
    {"type":"library","name":"release-gem","version":"3.0.0","purl":"pkg:gem/release-gem@3.0.0"}
  ]
}`),
	}
	provider := &fakeReleaseProvider{histories: map[string]ReleaseHistory{
		"npm:fresh-js": {
			Ecosystem: "npm", Name: "fresh-js",
			Versions: []Release{{Version: "1.0.0", PublishedAt: now.Add(-30 * 24 * time.Hour)}, {Version: "2.0.0", PublishedAt: now.Add(-time.Hour)}},
		},
		"pypi:quiet-python": {
			Ecosystem: "pypi", Name: "quiet-python",
			Versions: []Release{{Version: "1.0.0", PublishedAt: now.Add(-400 * 24 * time.Hour)}, {Version: "1.1.0", PublishedAt: now.Add(-2 * time.Hour)}},
		},
		"gem:release-gem": {
			Ecosystem: "gem", Name: "release-gem",
			Versions: []Release{{Version: "2.0.0", PublishedAt: now.Add(-20 * 24 * time.Hour)}, {Version: "3.0.0", PublishedAt: now.Add(-90 * time.Minute)}},
		},
	}}
	scanner := NewScanner(auditor)
	scanner.releaseProvider = provider

	report, err := scanner.ScanReleaseIntel(context.Background(), []string{"/repo"}, ReleaseIntelOptions{
		Cooldown: 72 * time.Hour, DormancyThreshold: 365 * 24 * time.Hour,
		BurstWindow: 2 * time.Hour, BurstThreshold: 3, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("ScanReleaseIntel: %v", err)
	}
	if auditor.format != "cyclonedx" || len(report.Components) != 3 {
		t.Fatalf("native component extraction = format %q components %+v", auditor.format, report.Components)
	}
	for _, id := range []string{DependencyCooldownID, DormantPackageResurrectionID, DependencyReleaseBurstID} {
		if !reportContainsFinding(report, id) {
			t.Errorf("report findings %+v missing %s", report.Findings, id)
		}
	}
	for _, component := range report.Components {
		if component.Version == "" || component.PublishedAt.IsZero() {
			t.Errorf("component missing exact release metadata: %+v", component)
		}
	}
}

func TestScannerScanReleaseIntelKeepsAuditWhenRegistryMetadataFails(t *testing.T) {
	auditor := &fakeSBOMAuditor{
		fakeAuditor: fakeAuditor{result: AuditResult{Dependencies: 1}},
		sbom:        []byte(`{"bomFormat":"CycloneDX","components":[{"name":"safe-fixture","version":"1.0.0","purl":"pkg:npm/safe-fixture@1.0.0"}]}`),
	}
	scanner := NewScanner(auditor)
	scanner.releaseProvider = &fakeReleaseProvider{err: errors.New("registry unavailable")}

	report, err := scanner.ScanReleaseIntel(context.Background(), []string{"/repo"}, ReleaseIntelOptions{Cooldown: 24 * time.Hour})
	if err != nil {
		t.Fatalf("ScanReleaseIntel: %v", err)
	}
	if report.Dependencies != 1 || len(report.Warnings) != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestScannerScanReleaseIntelRejectsInvalidNativeSBOM(t *testing.T) {
	scanner := NewScanner(&fakeSBOMAuditor{sbom: []byte(`{"bomFormat":"CycloneDX","components":`)})
	scanner.releaseProvider = &fakeReleaseProvider{}
	if _, err := scanner.ScanReleaseIntel(context.Background(), nil, ReleaseIntelOptions{Cooldown: time.Hour}); err == nil {
		t.Fatal("expected malformed native SBOM error")
	}
}

func reportContainsFinding(report Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
