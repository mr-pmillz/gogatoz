package cmd

import (
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/depscan"
)

func TestBuildGLDependencyScanningIncludesReleaseIntelFindings(t *testing.T) {
	report := depscan.Report{
		Lockfiles: []depscan.Lockfile{{Path: "package-lock.json"}},
		Packages: []depscan.AuditFinding{{
			Verdict: "malicious", Ecosystem: "npm", Name: "synthetic-bad", Version: "1.0.0",
			Source: "package-lock.json", IDs: []string{"MAL-2099-SYNTHETIC"},
		}},
		Components: []depscan.DependencyComponent{{
			Ecosystem: "npm", Name: "fresh-safe", Version: "2.0.0", PURL: "pkg:npm/fresh-safe@2.0.0",
		}},
		Findings: []analyze.Finding{
			{ID: analyze.MaliciousDependencyID, Severity: analyze.SeverityCritical, Title: "malicious", Evidence: "ecosystem=npm package=synthetic-bad version=1.0.0"},
			{ID: depscan.DependencyCooldownID, Severity: analyze.SeverityMedium, Title: "cooldown", Evidence: "ecosystem=npm package=fresh-safe version=2.0.0"},
		},
	}
	output := buildGLDependencyScanning(report, "test", time.Now(), time.Now())
	if len(output.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %+v", output.Vulnerabilities)
	}
	cooldown := output.Vulnerabilities[1]
	if cooldown.Location.Dependency.Package.Name != "fresh-safe" || cooldown.Location.Dependency.Version != "2.0.0" ||
		cooldown.Location.File != "package-lock.json" {
		t.Fatalf("cooldown vulnerability = %+v", cooldown)
	}
}
