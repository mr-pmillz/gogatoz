package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const glsastSchemaVersion = "15.0.4"

// glsastReport is the top-level GitLab SAST report (schema v15.0.4).
type glsastReport struct {
	Version         string       `json:"version"`
	Scan            glsastScan   `json:"scan"`
	Vulnerabilities []glsastVuln `json:"vulnerabilities"`
}

type glsastScan struct {
	Scanner   glsastScanner `json:"scanner"`
	Analyzer  glsastScanner `json:"analyzer"`
	Type      string        `json:"type"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Status    string        `json:"status"`
}

type glsastScanner struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Vendor  glsastVendor `json:"vendor"`
}

type glsastVendor struct {
	Name string `json:"name"`
}

type glsastVuln struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	Solution    string             `json:"solution,omitempty"`
	Scanner     glsastVulnScanner  `json:"scanner"`
	Identifiers []glsastIdentifier `json:"identifiers"`
	Location    glsastLocation     `json:"location"`
}

type glsastVulnScanner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type glsastIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type glsastLocation struct {
	File string `json:"file"`
}

// mapSeverity converts an analyze.Severity to the GitLab SAST severity string.
func mapSeverity(s analyze.Severity) string {
	switch s {
	case analyze.SeverityCritical:
		return "Critical"
	case analyze.SeverityHigh:
		return "High"
	case analyze.SeverityMedium:
		return "Medium"
	case analyze.SeverityLow:
		return "Low"
	case analyze.SeverityInformational:
		return "Info"
	default:
		return "Unknown"
	}
}

// vulnID produces a stable, deterministic SHA-256 identifier for a finding
// so that GitLab can deduplicate vulnerabilities across runs.
func vulnID(f analyze.Finding) string {
	h := sha256.Sum256([]byte(f.ID + "|" + f.JobName + "|" + f.Evidence))
	return fmt.Sprintf("%x", h)
}

// vulnSolution returns the recommendation text for a finding, falling back
// to the finding code registry when the finding itself has none.
func vulnSolution(f analyze.Finding) string {
	if f.Recommendation != "" {
		return f.Recommendation
	}
	if info := analyze.LookupFinding(f.ID); info != nil {
		return info.Remediation
	}
	return ""
}

// vulnDescription combines evidence and description into a single field.
func vulnDescription(f analyze.Finding) string {
	if f.Evidence != "" && f.Description != "" {
		return f.Evidence + "\n\n" + f.Description
	}
	if f.Evidence != "" {
		return f.Evidence
	}
	return f.Description
}

// buildGLSAST constructs a GitLab SAST report from analysis findings.
func buildGLSAST(findings []analyze.Finding, toolVersion string, startTime, endTime time.Time) glsastReport {
	scanner := glsastScanner{
		ID:      "gogatoz",
		Name:    "GoGatoZ",
		Version: toolVersion,
		Vendor:  glsastVendor{Name: "mr-pmillz"},
	}

	vulns := make([]glsastVuln, 0, len(findings))
	for _, f := range findings {
		vulns = append(vulns, glsastVuln{
			ID:          vulnID(f),
			Name:        f.Title,
			Description: vulnDescription(f),
			Severity:    mapSeverity(f.Severity),
			Solution:    vulnSolution(f),
			Scanner: glsastVulnScanner{
				ID:   "gogatoz",
				Name: "GoGatoZ",
			},
			Identifiers: []glsastIdentifier{
				{
					Type:  "gogatoz_finding_id",
					Name:  f.ID,
					Value: f.ID,
				},
			},
			Location: glsastLocation{
				File: ".gitlab-ci.yml",
			},
		})
	}

	return glsastReport{
		Version: glsastSchemaVersion,
		Scan: glsastScan{
			Scanner:   scanner,
			Analyzer:  scanner,
			Type:      "sast",
			StartTime: startTime.Format(time.RFC3339),
			EndTime:   endTime.Format(time.RFC3339),
			Status:    "success",
		},
		Vulnerabilities: vulns,
	}
}

// WriteGLSAST serializes a GitLab SAST report to w as indented JSON.
func WriteGLSAST(w io.Writer, findings []analyze.Finding, toolVersion string, startTime, endTime time.Time) error {
	report := buildGLSAST(findings, toolVersion, startTime, endTime)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
