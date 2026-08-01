package depscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

type archiveAuditor struct {
	paths []string
}

func (a *archiveAuditor) Audit(_ context.Context, paths []string) (AuditResult, error) {
	a.paths = append([]string(nil), paths...)
	source := filepath.Join(paths[0], "safe-project-deadbeef", "bom.cdx.json")
	return AuditResult{
		Paths:        append([]string(nil), paths...),
		Dependencies: 1,
		Summary:      AuditSummary{Lockfiles: 1, Total: 1, Malicious: 1},
		Lockfiles:    []Lockfile{{Path: source, Type: "sbom", Ecosystem: "npm", Dependencies: 1}},
		Findings: []AuditFinding{{
			Verdict: "malicious", Ecosystem: "npm", Name: "gogatoz-synthetic-malicious",
			Version: "1.2.3", IDs: []string{"MAL-2099-GOGATOZ-TEST"}, Source: source,
		}},
	}, nil
}

func (a *archiveAuditor) Close() {}

func TestScanner_ScanGitLabProjectUsesBoundedArchiveAndRelativeLocations(t *testing.T) {
	archive := makeTarGz(t, []tarEntry{{
		name: "safe-project-deadbeef/bom.cdx.json",
		body: `{"bomFormat":"CycloneDX","components":[]}`,
	}})
	var requestedSHA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repository/archive.tar.gz") {
			http.NotFound(w, r)
			return
		}
		requestedSHA = r.URL.Query().Get("sha")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	client, err := gitlabx.New(server.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}
	auditor := &archiveAuditor{}
	scanner := NewScanner(auditor)

	report, err := scanner.ScanGitLabProject(context.Background(), client, 42, " main ")
	if err != nil {
		t.Fatalf("ScanGitLabProject: %v", err)
	}
	if requestedSHA != "main" {
		t.Fatalf("requested sha = %q, want main", requestedSHA)
	}
	if len(auditor.paths) != 2 || auditor.paths[0] == "" ||
		!strings.HasSuffix(auditor.paths[1], filepath.Join("safe-project-deadbeef", "bom.cdx.json")) {
		t.Fatalf("audit paths = %v, want extraction root plus explicit SBOM path", auditor.paths)
	}
	if len(report.Lockfiles) != 1 || report.Lockfiles[0].Path != "bom.cdx.json" {
		t.Fatalf("lockfiles = %+v, want repository-relative bom.cdx.json", report.Lockfiles)
	}
	if len(report.Paths) != 2 || report.Paths[0] != "." || report.Paths[1] != "bom.cdx.json" {
		t.Fatalf("report paths = %v, want repository-relative audit paths", report.Paths)
	}
	if len(report.Findings) != 1 || report.Findings[0].SourceFile != "bom.cdx.json" {
		t.Fatalf("findings = %+v, want repository-relative bom.cdx.json", report.Findings)
	}
	if strings.Contains(report.Findings[0].Evidence, auditor.paths[0]) {
		t.Fatalf("evidence leaked temporary extraction path: %q", report.Findings[0].Evidence)
	}
}
