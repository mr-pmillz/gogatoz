package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/config"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Finding ID constants for container image supply chain checks.
const (
	ImageMutableTagID = "IMAGE_MUTABLE_TAG"
	ImageNotPinnedID  = "IMAGE_NOT_PINNED"
)

// forbiddenMutableTags lists tags that are inherently mutable and make builds
// non-reproducible. Compared case-insensitively.
var forbiddenMutableTags = []string{
	"latest",
	"dev",
	"master",
	"main",
	"nightly",
	"edge",
	"canary",
	"unstable",
	"beta",
	"alpha",
	"rc",
	"staging",
}

// parseImageRef splits a Docker/OCI image reference into its components.
// Supported formats:
//
//	name
//	name:tag
//	name@sha256:xxx
//	name:tag@sha256:xxx
//	registry/name:tag
//	registry:port/name:tag
//
// If no tag and no digest are present, tag defaults to "latest".
func parseImageRef(ref string) (registry, name, tag, digest string) {
	s := strings.TrimSpace(ref)
	if s == "" {
		return
	}

	// Split off digest first: everything after @sha256:
	if idx := strings.Index(s, "@sha256:"); idx >= 0 {
		digest = s[idx+1:] // "sha256:xxx"
		s = s[:idx]
	}

	// Now s is the name[:tag] portion, possibly with registry.
	// Find the tag: the last ":" that is part of a tag, not a port.
	// A colon is a tag separator if it appears after the last "/" (or if there
	// is no "/"). A colon before the first "/" could be a registry port.
	lastSlash := strings.LastIndex(s, "/")
	colonIdx := strings.LastIndex(s, ":")
	if colonIdx > lastSlash {
		// colon is after the last slash → it's a tag separator
		tag = s[colonIdx+1:]
		s = s[:colonIdx]
	}

	// s is now the registry+name portion (no tag, no digest).
	// Split into registry vs name. Heuristic: if the first path component
	// contains a "." or ":" (port) or is "localhost", treat it as a registry.
	if before, after, ok := strings.Cut(s, "/"); ok {
		first := before
		if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
			registry = first
			name = after
		} else {
			name = s
		}
	} else {
		name = s
	}

	// Implicit latest when neither tag nor digest is specified.
	if tag == "" && digest == "" {
		tag = "latest"
	}

	return registry, name, tag, digest
}

// isMutableTag returns true if tag matches a known mutable tag (case-insensitive)
// or matches the short version-only pattern (e.g., "v1", "v12" but not "v1.2.3").
// It uses the default forbiddenMutableTags list.
func isMutableTag(tag string) bool {
	return isMutableTagIn(tag, forbiddenMutableTags)
}

// isMutableTagIn returns true if tag matches any entry in the provided tags list
// (case-insensitive) or matches the short version-only pattern (e.g., "v1", "v12").
func isMutableTagIn(tag string, tags []string) bool {
	lower := strings.ToLower(tag)
	for _, ft := range tags {
		if lower == strings.ToLower(ft) {
			return true
		}
	}
	// Glob-like: tags that are just "v" + major version number (e.g. v1, v12)
	// but NOT v1.2.3 or v1-alpine etc.
	if len(lower) >= 2 && lower[0] == 'v' {
		rest := lower[1:]
		allDigits := true
		for _, ch := range rest {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

// detectImageIssues checks container images in jobs and the document-level
// default image for mutable tags and missing digest pinning.
// When controls is non-nil and ForbiddenImageTags is non-empty, those tags
// replace the default forbiddenMutableTags list.
func detectImageIssues(doc *pipeline.Document, controls *config.ControlsConfig) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}

	tags := forbiddenMutableTags
	if controls != nil && len(controls.ForbiddenImageTags) > 0 {
		tags = controls.ForbiddenImageTags
	}

	// Collect all (image, jobName) pairs to check.
	type imageEntry struct {
		ref     string
		jobName string // empty for document-level default image
	}
	var images []imageEntry

	// Document-level default image (top-level `image:` key).
	if defaultImg := extractDefaultImage(doc); defaultImg != "" {
		images = append(images, imageEntry{ref: defaultImg})
	}

	// Per-job images and services.
	for _, job := range doc.Jobs {
		if job.Image != "" {
			images = append(images, imageEntry{ref: job.Image, jobName: job.Name})
		}
		for _, svc := range job.Services {
			images = append(images, imageEntry{ref: svc, jobName: job.Name})
		}
	}

	for _, img := range images {
		// Skip unresolvable variable references.
		if strings.Contains(img.ref, "$") {
			continue
		}

		_, _, tag, digest := parseImageRef(img.ref)

		// IMAGE_MUTABLE_TAG: flag mutable tags (skip digest-pinned images).
		if digest == "" && isMutableTagIn(tag, tags) {
			evidence := fmt.Sprintf("image=%s tag=%s", img.ref, tag)
			if img.jobName != "" {
				evidence += fmt.Sprintf(" job=%s", img.jobName)
			}
			findings = append(findings, Finding{
				ID:          ImageMutableTagID,
				Severity:    SeverityMedium,
				Title:       "Container image uses mutable tag",
				Description: "Container image uses a mutable tag (e.g., 'latest', 'dev'). Mutable tags make builds non-reproducible because the underlying image can change without notice, introducing supply chain risks.",
				Evidence:    evidence,
				JobName:     img.jobName,
			})
		}

		// IMAGE_NOT_PINNED: flag images without a sha256 digest.
		if digest == "" {
			evidence := fmt.Sprintf("image=%s", img.ref)
			if img.jobName != "" {
				evidence += fmt.Sprintf(" job=%s", img.jobName)
			}
			findings = append(findings, Finding{
				ID:          ImageNotPinnedID,
				Severity:    SeverityHigh,
				Title:       "Container image not pinned by digest",
				Description: "Container image is not pinned by its SHA256 digest. Without digest pinning, a tag can be reassigned to a different image at the registry level, introducing supply chain risks.",
				Evidence:    evidence,
				JobName:     img.jobName,
			})
		}
	}

	return findings
}

// extractDefaultImage reads the top-level `image:` key from the raw document.
// It handles both string values and mapping values with a `name` key.
func extractDefaultImage(doc *pipeline.Document) string {
	if doc.Raw == nil {
		return ""
	}
	img, ok := doc.Raw["image"]
	if !ok {
		return ""
	}
	if s, ok := img.(string); ok {
		return s
	}
	if m, ok := img.(map[string]any); ok {
		if name, ok := m["name"].(string); ok {
			return name
		}
	}
	return ""
}
