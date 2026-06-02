package secretscan

import (
	"testing"
)

//nolint:gosec // test credentials are intentional
func TestParseTrufflehogOutput(t *testing.T) {
	sample := `{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/repo/config.yaml","line":12}}},"SourceType":15,"SourceID":0,"DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE","RawV2":"","ExtraData":{"account":"123456789"}}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/repo/.env","line":3}}},"SourceType":15,"SourceID":0,"DetectorType":9,"DetectorName":"GitHubToken","DecoderName":"PLAIN","Verified":false,"Raw":"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","RawV2":"ghp_yyyyyyyyyyyy","ExtraData":{}}
not a json line
`
	findings, err := parseTrufflehogOutput([]byte(sample))
	if err != nil {
		t.Fatalf("parseTrufflehogOutput() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	// First finding
	f := findings[0]
	if f.Scanner != "trufflehog" {
		t.Errorf("Scanner = %q", f.Scanner)
	}
	if f.RuleID != "AWS" {
		t.Errorf("RuleID = %q, want AWS", f.RuleID)
	}
	if f.File != "/tmp/repo/config.yaml" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != 12 {
		t.Errorf("Line = %d, want 12", f.Line)
	}
	if f.Secret != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Secret = %q", f.Secret)
	}
	if !f.Verified {
		t.Error("expected Verified=true")
	}

	// Second finding should use RawV2
	f2 := findings[1]
	if f2.Secret != "ghp_yyyyyyyyyyyy" {
		t.Errorf("expected RawV2 to be used, got Secret = %q", f2.Secret)
	}
}

func TestParseTrufflehogOutput_empty(t *testing.T) {
	findings, err := parseTrufflehogOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

//nolint:gosec // test credentials are intentional
func TestParseGitleaksOutput(t *testing.T) {
	sample := `[
  {
    "RuleID": "aws-access-key",
    "Description": "AWS Access Key",
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config.yaml",
    "StartLine": 5,
    "Commit": "abc123",
    "Author": "dev@example.com",
    "Date": "2024-01-15",
    "Entropy": 3.84,
    "Fingerprint": "config.yaml:aws-access-key:5"
  },
  {
    "RuleID": "generic-api-key",
    "Description": "Generic API Key",
    "Match": "api_key=supersecret",
    "Secret": "",
    "File": ".env",
    "StartLine": 1,
    "Commit": "def456",
    "Author": "admin@example.com",
    "Date": "2024-02-20",
    "Entropy": 2.5,
    "Fingerprint": ".env:generic-api-key:1"
  }
]`

	findings, err := parseGitleaksOutput([]byte(sample))
	if err != nil {
		t.Fatalf("parseGitleaksOutput() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	f := findings[0]
	if f.Scanner != "gitleaks" {
		t.Errorf("Scanner = %q", f.Scanner)
	}
	if f.RuleID != "aws-access-key" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Entropy != 3.84 {
		t.Errorf("Entropy = %f, want 3.84", f.Entropy)
	}

	// Second finding should use Match when Secret is empty
	f2 := findings[1]
	if f2.Secret != "api_key=supersecret" {
		t.Errorf("expected Match to be used when Secret is empty, got %q", f2.Secret)
	}
}

func TestParseGitleaksOutput_empty(t *testing.T) {
	findings, err := parseGitleaksOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

//nolint:gosec // test credentials are intentional
func TestParseTitusOutput_sarif(t *testing.T) {
	sample := `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "titus", "version": "0.1.0", "rules": []}},
    "results": [
      {
        "ruleId": "np.gitlab.2",
        "level": "warning",
        "message": {"text": "GitLab Personal Access Token"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "file:///tmp/repo/.gitlab-ci.yml"},
            "region": {
              "startLine": 3,
              "startColumn": 21,
              "endLine": 3,
              "endColumn": 47,
              "snippet": {"text": "glpat-Kf9mXn3vR7pQs2wYu8aB"}
            }
          }
        }]
      },
      {
        "ruleId": "np.aws.1",
        "level": "error",
        "message": {"text": "AWS Access Key"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "file:///tmp/repo/config.env"},
            "region": {
              "startLine": 5,
              "snippet": {"text": "AKIAIOSFODNN7EXAMPLE"}
            }
          }
        }]
      }
    ]
  }]
}`
	findings, err := parseTitusOutput([]byte(sample))
	if err != nil {
		t.Fatalf("parseTitusOutput() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	f := findings[0]
	if f.Scanner != "titus" {
		t.Errorf("Scanner = %q", f.Scanner)
	}
	if f.RuleID != "np.gitlab.2" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Description != "GitLab Personal Access Token" {
		t.Errorf("Description = %q", f.Description)
	}
	if f.File != "/tmp/repo/.gitlab-ci.yml" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != 3 {
		t.Errorf("Line = %d, want 3", f.Line)
	}
	if f.Secret != "glpat-Kf9mXn3vR7pQs2wYu8aB" {
		t.Errorf("Secret = %q", f.Secret)
	}
	if f.Severity != "MEDIUM" {
		t.Errorf("Severity = %q, want MEDIUM", f.Severity)
	}

	f2 := findings[1]
	if f2.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", f2.Severity)
	}
}

func TestParseTitusOutput_empty(t *testing.T) {
	findings, err := parseTitusOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTitusOutput_noResults(t *testing.T) {
	sample := `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{"tool": {"driver": {"name": "titus", "version": "0.1.0", "rules": []}}, "results": []}]
}`
	findings, err := parseTitusOutput([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAllScanners(t *testing.T) {
	scanners := AllScanners()
	if len(scanners) != 3 {
		t.Fatalf("AllScanners() returned %d, want 3", len(scanners))
	}
	names := map[string]bool{}
	for _, s := range scanners {
		names[s.Name] = true
	}
	for _, want := range []string{"trufflehog", "gitleaks", "titus"} {
		if !names[want] {
			t.Errorf("missing scanner %q", want)
		}
	}
}

func TestParseScanners_unknownName(t *testing.T) {
	_, err := ParseScanners("nosuchscanner")
	if err == nil {
		t.Fatal("expected error for unknown scanner")
	}
}

func TestParseScanners_empty(t *testing.T) {
	_, err := ParseScanners(",,,")
	if err == nil {
		t.Fatal("expected error for empty scanners")
	}
}
