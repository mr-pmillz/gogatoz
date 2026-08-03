package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/depscan"
)

const glDependencySchemaVersion = "15.2.4"

type glDependencyReport struct {
	Schema          string             `json:"schema,omitempty"`
	Version         string             `json:"version"`
	Scan            glDependencyScan   `json:"scan"`
	Vulnerabilities []glDependencyVuln `json:"vulnerabilities"`
}

type glDependencyScan struct {
	Scanner   glsastScanner `json:"scanner"`
	Analyzer  glsastScanner `json:"analyzer"`
	Type      string        `json:"type"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Status    string        `json:"status"`
}

type glDependencyVuln struct {
	ID          string               `json:"id"`
	Name        string               `json:"name,omitempty"`
	Description string               `json:"description,omitempty"`
	Severity    string               `json:"severity,omitempty"`
	Solution    string               `json:"solution,omitempty"`
	Scanner     glsastVulnScanner    `json:"scanner,omitempty"`
	Identifiers []glsastIdentifier   `json:"identifiers"`
	Location    glDependencyLocation `json:"location"`
}

type glDependencyLocation struct {
	File       string                 `json:"file"`
	Dependency glDependencyCoordinate `json:"dependency"`
}

type glDependencyCoordinate struct {
	Package glDependencyPackage `json:"package"`
	Version string              `json:"version"`
}

type glDependencyPackage struct {
	Name string `json:"name"`
}

func buildGLDependencyScanning(report depscan.Report, toolVersion string, startTime, endTime time.Time) glDependencyReport {
	scanner := glsastScanner{
		ID: "gogatoz", Name: "GoGatoZ", Version: toolVersion,
		Vendor: glsastVendor{Name: "mr-pmillz"},
	}
	vulnerabilities := make([]glDependencyVuln, 0, len(report.Findings))
	for _, finding := range report.Findings {
		pkg := dependencyCoordinateForFinding(report, finding)
		identifiers := packageIdentifiers(pkg, finding.ID)
		file := strings.TrimSpace(pkg.Source)
		if file == "" {
			file = strings.TrimSpace(pkg.Lockfile)
		}
		if file == "" {
			file = findingSourceFile(finding)
		}
		vulnerabilities = append(vulnerabilities, glDependencyVuln{
			ID:          dependencyVulnID(pkg, finding.ID),
			Name:        finding.Title,
			Description: vulnDescription(finding),
			Severity:    mapSeverity(finding.Severity),
			Solution:    vulnSolution(finding),
			Scanner:     glsastVulnScanner{ID: "gogatoz", Name: "GoGatoZ"},
			Identifiers: identifiers,
			Location: glDependencyLocation{
				File: file,
				Dependency: glDependencyCoordinate{
					Package: glDependencyPackage{Name: pkg.Name},
					Version: pkg.Version,
				},
			},
		})
	}
	return glDependencyReport{
		Schema:  "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.2.4/dist/dependency-scanning-report-format.json",
		Version: glDependencySchemaVersion,
		Scan: glDependencyScan{
			Scanner: scanner, Analyzer: scanner, Type: "dependency_scanning",
			StartTime: gitLabSecurityTime(startTime), EndTime: gitLabSecurityTime(endTime), Status: "success",
		},
		Vulnerabilities: vulnerabilities,
	}
}

func dependencyCoordinateForFinding(report depscan.Report, finding analyze.Finding) depscan.AuditFinding {
	name := evidenceValue(finding.Evidence, "package")
	version := evidenceValue(finding.Evidence, "version")
	ecosystem := evidenceValue(finding.Evidence, "ecosystem")
	for _, pkg := range report.Packages {
		if dependencyIdentityMatches(pkg.Ecosystem, pkg.Name, pkg.Version, ecosystem, name, version) {
			return pkg
		}
	}
	for _, component := range report.Components {
		if dependencyIdentityMatches(component.Ecosystem, component.Name, component.Version, ecosystem, name, version) {
			return depscan.AuditFinding{
				Ecosystem: component.Ecosystem, Name: component.Name, Version: component.Version,
				Source: dependencyReportSource(report, finding), PackageURL: component.PURL,
			}
		}
	}
	return depscan.AuditFinding{
		Ecosystem: ecosystem, Name: name, Version: version,
		Source: dependencyReportSource(report, finding),
	}
}

func dependencyIdentityMatches(pkgEcosystem, pkgName, pkgVersion, ecosystem, name, version string) bool {
	return strings.EqualFold(strings.TrimSpace(pkgEcosystem), strings.TrimSpace(ecosystem)) &&
		strings.EqualFold(strings.TrimSpace(pkgName), strings.TrimSpace(name)) &&
		strings.TrimSpace(pkgVersion) == strings.TrimSpace(version)
}

func dependencyReportSource(report depscan.Report, finding analyze.Finding) string {
	if source := strings.TrimSpace(finding.SourceFile); source != "" {
		return source
	}
	if len(report.Lockfiles) > 0 && strings.TrimSpace(report.Lockfiles[0].Path) != "" {
		return strings.TrimSpace(report.Lockfiles[0].Path)
	}
	return "dependency-metadata"
}

func evidenceValue(evidence, key string) string {
	prefix := key + "="
	for _, field := range strings.Fields(evidence) {
		if value, ok := strings.CutPrefix(field, prefix); ok {
			return strings.TrimSpace(strings.TrimSuffix(value, ","))
		}
	}
	return ""
}

func packageIdentifiers(pkg depscan.AuditFinding, fallback string) []glsastIdentifier {
	ids := pkg.IDs
	if len(ids) == 0 {
		ids = []string{fallback}
	}
	out := make([]glsastIdentifier, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		identifierType := "depx"
		upper := strings.ToUpper(id)
		if strings.HasPrefix(upper, "CVE-") {
			identifierType = "cve"
		} else if strings.HasPrefix(upper, "GHSA-") {
			identifierType = "ghsa"
		}
		out = append(out, glsastIdentifier{Type: identifierType, Name: id, Value: id})
	}
	if len(out) == 0 {
		out = append(out, glsastIdentifier{Type: "gogatoz_finding_id", Name: fallback, Value: fallback})
	}
	return out
}

func dependencyVulnID(pkg depscan.AuditFinding, findingID string) string {
	input := strings.Join([]string{findingID, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source, strings.Join(pkg.IDs, ",")}, "|")
	digest := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", digest)
}

func gitLabSecurityTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05")
}

func WriteGLDependencyScanning(writer io.Writer, report depscan.Report, toolVersion string, startTime, endTime time.Time) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(buildGLDependencyScanning(report, toolVersion, startTime, endTime))
}
