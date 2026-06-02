package secretscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Scanner runs a secret detection tool against a local directory.
type Scanner struct {
	Name       string
	BinaryName string
	scanFn     func(ctx context.Context, repoPath string) ([]SecretFinding, error)
}

// Available reports whether the scanner binary is on PATH.
func (s *Scanner) Available() bool {
	_, err := exec.LookPath(s.BinaryName)
	return err == nil
}

// Scan runs the scanner against the given repo path and returns findings.
func (s *Scanner) Scan(ctx context.Context, repoPath string) ([]SecretFinding, error) {
	return s.scanFn(ctx, repoPath)
}

// AllScanners returns the full set of supported scanners.
func AllScanners() []*Scanner {
	return []*Scanner{
		trufflehogScanner(),
		gitleaksScanner(),
		titusScanner(),
	}
}

// DetectScanners returns only the scanners whose binaries are available.
func DetectScanners() []*Scanner {
	var available []*Scanner
	for _, s := range AllScanners() {
		if s.Available() {
			available = append(available, s)
		}
	}
	return available
}

// ParseScanners parses a comma-separated scanner list. "auto" detects
// available scanners. Returns an error if a named scanner is not recognized
// or if no scanners are available.
func ParseScanners(csv string) ([]*Scanner, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" || strings.EqualFold(csv, "auto") {
		scanners := DetectScanners()
		if len(scanners) == 0 {
			return nil, fmt.Errorf("no secret scanners found on PATH (install trufflehog, gitleaks, or titus)")
		}
		return scanners, nil
	}

	all := AllScanners()
	byName := make(map[string]*Scanner, len(all))
	for _, s := range all {
		byName[s.Name] = s
	}

	var scanners []*Scanner
	for _, name := range strings.Split(csv, ",") {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		s, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown scanner %q: use trufflehog, gitleaks, or titus", name)
		}
		if !s.Available() {
			return nil, fmt.Errorf("scanner %q not found on PATH", name)
		}
		scanners = append(scanners, s)
	}
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners specified")
	}
	return scanners, nil
}

// --- TruffleHog -----------------------------------------------------------

func trufflehogScanner() *Scanner {
	return &Scanner{
		Name:       "trufflehog",
		BinaryName: "trufflehog",
		scanFn:     runTrufflehog,
	}
}

func runTrufflehog(ctx context.Context, repoPath string) ([]SecretFinding, error) {
	cmd := exec.CommandContext(ctx, "trufflehog", "filesystem", "--json", "--no-update", repoPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() // trufflehog exits non-zero when secrets found

	return parseTrufflehogOutput(stdout.Bytes())
}

// trufflehogResult represents a single TruffleHog JSON output line.
type trufflehogResult struct {
	DetectorName   string `json:"DetectorName"`
	DecoderName    string `json:"DecoderName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int64  `json:"line"`
			} `json:"Filesystem"`
			Git struct {
				Commit    string `json:"commit"`
				File      string `json:"file"`
				Email     string `json:"email"`
				Timestamp string `json:"timestamp"`
				Line      int64  `json:"line"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	ExtraData map[string]string `json:"ExtraData"`
}

func parseTrufflehogOutput(data []byte) ([]SecretFinding, error) {
	var findings []SecretFinding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var r trufflehogResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue // skip non-JSON lines
		}
		if r.DetectorName == "" {
			continue
		}

		secret := r.Raw
		if r.RawV2 != "" {
			secret = r.RawV2
		}

		file := r.SourceMetadata.Data.Filesystem.File
		lineNum := int(r.SourceMetadata.Data.Filesystem.Line)
		commit := r.SourceMetadata.Data.Git.Commit
		author := r.SourceMetadata.Data.Git.Email
		date := r.SourceMetadata.Data.Git.Timestamp

		if file == "" {
			file = r.SourceMetadata.Data.Git.File
		}
		if lineNum == 0 {
			lineNum = int(r.SourceMetadata.Data.Git.Line)
		}

		findings = append(findings, SecretFinding{
			Scanner:  "trufflehog",
			RuleID:   r.DetectorName,
			File:     file,
			Line:     lineNum,
			Secret:   secret,
			Verified: r.Verified,
			Commit:   commit,
			Author:   author,
			Date:     date,
		})
	}
	return findings, scanner.Err()
}

// --- Gitleaks -------------------------------------------------------------

func gitleaksScanner() *Scanner {
	return &Scanner{
		Name:       "gitleaks",
		BinaryName: "gitleaks",
		scanFn:     runGitleaks,
	}
}

func runGitleaks(ctx context.Context, repoPath string) ([]SecretFinding, error) {
	cmd := exec.CommandContext(ctx, "gitleaks", "dir", "--report-format", "json", "--report-path", "/dev/stdout", "--source", repoPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() // gitleaks exits non-zero when secrets found

	return parseGitleaksOutput(stdout.Bytes())
}

// gitleaksResult represents a single Gitleaks finding.
type gitleaksResult struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	Match       string  `json:"Match"`
	Secret      string  `json:"Secret"` //nolint:gosec // gitleaks finding field, not a credential
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	Commit      string  `json:"Commit"`
	Author      string  `json:"Author"`
	Date        string  `json:"Date"`
	Entropy     float64 `json:"Entropy"`
	Fingerprint string  `json:"Fingerprint"`
}

func parseGitleaksOutput(data []byte) ([]SecretFinding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var results []gitleaksResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("parse gitleaks JSON: %w", err)
	}

	findings := make([]SecretFinding, 0, len(results))
	for _, r := range results {
		secret := r.Secret
		if secret == "" {
			secret = r.Match
		}
		findings = append(findings, SecretFinding{
			Scanner:     "gitleaks",
			RuleID:      r.RuleID,
			Description: r.Description,
			File:        r.File,
			Line:        r.StartLine,
			Secret:      secret,
			Entropy:     r.Entropy,
			Commit:      r.Commit,
			Author:      r.Author,
			Date:        r.Date,
		})
	}
	return findings, nil
}

// --- Titus ----------------------------------------------------------------

func titusScanner() *Scanner {
	return &Scanner{
		Name:       "titus",
		BinaryName: "titus",
		scanFn:     runTitus,
	}
}

func runTitus(ctx context.Context, repoPath string) ([]SecretFinding, error) {
	cmd := exec.CommandContext(ctx, "titus", "scan", "--format", "sarif", "--output", ":memory:", "--include-hidden", repoPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() // titus may exit non-zero when secrets found

	return parseTitusOutput(stdout.Bytes())
}

// titusSARIF represents the SARIF output from titus scan.
type titusSARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
						Snippet   struct {
							Text string `json:"text"`
						} `json:"snippet"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseTitusOutput(data []byte) ([]SecretFinding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var sarif titusSARIF
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("parse titus SARIF: %w", err)
	}

	var findings []SecretFinding
	for _, run := range sarif.Runs {
		for _, r := range run.Results {
			f := SecretFinding{
				Scanner:     "titus",
				RuleID:      r.RuleID,
				Description: r.Message.Text,
			}

			// Map severity from SARIF level
			switch r.Level {
			case "error":
				f.Severity = "HIGH"
			case "warning":
				f.Severity = "MEDIUM"
			case "note":
				f.Severity = "LOW"
			}

			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				file := loc.ArtifactLocation.URI
				// Strip file:// prefix
				file = strings.TrimPrefix(file, "file://")
				f.File = file
				f.Line = loc.Region.StartLine
				f.Secret = loc.Region.Snippet.Text
			}

			findings = append(findings, f)
		}
	}
	return findings, nil
}
