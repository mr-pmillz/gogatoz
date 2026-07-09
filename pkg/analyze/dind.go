package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Finding ID constants for Docker-in-Docker detections.
const (
	DinDDetectedID = "DIND_DETECTED"
	DinDInsecureID = "DIND_INSECURE"
)

// isDinDService parses a service image reference and returns true if it
// matches the Docker-in-Docker pattern. A service is considered dind if:
//   - The image name (last path segment, ignoring tag) equals "docker" (case-insensitive)
//   - AND the tag is "dind", "latest", or contains "dind" (e.g., "24-dind", "25.0-dind")
//   - Bare "docker" without a tag is NOT dind
func isDinDService(service string) bool {
	service = strings.TrimSpace(service)
	if service == "" {
		return false
	}

	// Split image reference into name and tag on the last colon.
	// registry.example.com:5000/docker:dind -> name=registry.example.com:5000/docker, tag=dind
	// We split on the last colon that appears after the last slash.
	name := service
	tag := ""

	lastSlash := strings.LastIndex(service, "/")
	tagPart := service
	if lastSlash >= 0 {
		tagPart = service[lastSlash+1:]
	}

	if colonIdx := strings.Index(tagPart, ":"); colonIdx >= 0 {
		// Compute absolute position of colon
		absColon := colonIdx
		if lastSlash >= 0 {
			absColon = lastSlash + 1 + colonIdx
		}
		name = service[:absColon]
		tag = service[absColon+1:]
	}

	// Extract the image base name (last path segment of name)
	baseName := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		baseName = name[idx+1:]
	}

	// The base name must be "docker" (case-insensitive)
	if !strings.EqualFold(baseName, "docker") {
		return false
	}

	// No tag means bare "docker" -- not dind
	if tag == "" {
		return false
	}

	tagLower := strings.ToLower(tag)
	// Tag is "dind", "latest", or contains "dind"
	return tagLower == "dind" || tagLower == "latest" || strings.Contains(tagLower, "dind")
}

// detectDinD scans all jobs for Docker-in-Docker services and insecure daemon
// configuration. Returns DIND_DETECTED when a dind service is found in a job,
// and DIND_INSECURE when the dind service is paired with insecure settings
// (no TLS cert dir or unencrypted port 2375).
func detectDinD(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		// Find the first dind service in this job
		var dindService string
		for _, svc := range job.Services {
			if isDinDService(svc) {
				dindService = svc
				break
			}
		}
		if dindService == "" {
			continue
		}

		// Emit at most one DIND_DETECTED per job
		findings = append(findings, Finding{
			ID:          DinDDetectedID,
			Severity:    SeverityHigh,
			Title:       "Docker-in-Docker service detected",
			Description: "Job uses a Docker-in-Docker (dind) service. On shared runners running in privileged mode, this enables container escape, lateral movement, and access to secrets from other jobs on the same runner.",
			Evidence:    fmt.Sprintf("service=%s job=%s", dindService, job.Name),
			JobName:     job.Name,
		})

		// Check for insecure daemon configuration
		if insecureEvidence := checkDinDInsecure(job, doc); insecureEvidence != "" {
			findings = append(findings, Finding{
				ID:          DinDInsecureID,
				Severity:    SeverityHigh,
				Title:       "Docker-in-Docker with insecure daemon configuration",
				Description: "Docker-in-Docker service runs with TLS disabled or uses unencrypted port 2375. This exposes the Docker daemon to network attacks and allows interception of build secrets.",
				Evidence:    fmt.Sprintf("%s job=%s", insecureEvidence, job.Name),
				JobName:     job.Name,
			})
		}
	}
	return findings
}

// checkDinDInsecure checks whether a job with a dind service has insecure
// daemon configuration. It inspects both job-level and global document variables
// for DOCKER_TLS_CERTDIR and DOCKER_HOST settings.
// Returns a non-empty evidence string if insecure configuration is found.
func checkDinDInsecure(job pipeline.Job, doc *pipeline.Document) string {
	// Resolve effective variable values: job-level overrides global
	tlsCertDir, tlsCertDirSet := resolveVariable(job, doc, "DOCKER_TLS_CERTDIR")
	dockerHost, dockerHostSet := resolveVariable(job, doc, "DOCKER_HOST")

	// DOCKER_TLS_CERTDIR set to empty string disables TLS
	if tlsCertDirSet && tlsCertDir == "" {
		return "DOCKER_TLS_CERTDIR=\"\" (TLS disabled)"
	}

	// DOCKER_HOST set to tcp://...:2375 (unencrypted port)
	if dockerHostSet && strings.Contains(strings.ToLower(dockerHost), ":2375") {
		return fmt.Sprintf("DOCKER_HOST=%s (unencrypted port)", dockerHost)
	}

	// DOCKER_TLS_CERTDIR not set at all when dind is present
	if !tlsCertDirSet {
		return "DOCKER_TLS_CERTDIR not set (TLS may be disabled by default on older dind images)"
	}

	return ""
}

// resolveVariable looks up a variable name in job-level variables first, then
// falls back to global document variables. Returns the string value and whether
// the variable was found at either level.
func resolveVariable(job pipeline.Job, doc *pipeline.Document, name string) (string, bool) {
	// Job-level takes precedence
	if job.Variables != nil {
		if v, ok := job.Variables[name]; ok {
			return extractVarValue(v)
		}
	}

	// Fall back to global variables
	if doc.Variables != nil {
		if v, ok := doc.Variables[name]; ok {
			return extractVarValue(v)
		}
	}

	return "", false
}
