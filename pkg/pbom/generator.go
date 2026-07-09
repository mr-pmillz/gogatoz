package pbom

import (
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// Generator builds a PBOM from a parsed pipeline document.
type Generator struct {
	projectPath string
	projectID   int64
	url         string
	branch      string
}

// NewGenerator creates a Generator for the given project.
func NewGenerator(projectPath string, projectID int64, url, branch string) *Generator {
	return &Generator{
		projectPath: projectPath,
		projectID:   projectID,
		url:         url,
		branch:      branch,
	}
}

// Generate builds a PBOM from a parsed pipeline Document. It extracts all
// container images (default, per-job, and services) and all CI includes,
// deduplicating images by their full reference string.
func (g *Generator) Generate(doc *pipeline.Document) *PBOM {
	now := time.Now().UTC()
	p := &PBOM{
		PBOMVersion: Version,
		GeneratedAt: now,
		Project: ProjectInfo{
			Path:   g.projectPath,
			ID:     g.projectID,
			URL:    g.url,
			Branch: g.branch,
		},
	}

	if doc == nil {
		p.ContainerImages = []ContainerImage{}
		p.Includes = []PBOMInclude{}
		return p
	}

	p.ContainerImages = g.collectImages(doc)
	p.Includes = g.collectIncludes(doc)
	p.Summary = Summary{
		TotalImages:   countTotalImageRefs(doc),
		TotalIncludes: len(p.Includes),
		UniqueImages:  len(p.ContainerImages),
	}

	return p
}

// countTotalImageRefs counts every image reference (default + per-job images + services)
// before deduplication.
func countTotalImageRefs(doc *pipeline.Document) int {
	total := 0
	if extractDefaultImage(doc) != "" {
		total++
	}
	for _, job := range doc.Jobs {
		if job.Image != "" {
			total++
		}
		total += len(job.Services)
	}
	return total
}

// collectImages extracts all container image references from the document,
// deduplicating by the full image reference string. Each unique image tracks
// which jobs reference it.
func (g *Generator) collectImages(doc *pipeline.Document) []ContainerImage {
	// Ordered dedup: track insertion order and accumulate job names.
	type entry struct {
		ref  string
		jobs []string
	}
	seen := make(map[string]int) // ref -> index in entries
	var entries []entry

	addImage := func(ref, jobName string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if idx, ok := seen[ref]; ok {
			if jobName != "" {
				entries[idx].jobs = append(entries[idx].jobs, jobName)
			}
			return
		}
		var jobs []string
		if jobName != "" {
			jobs = []string{jobName}
		}
		seen[ref] = len(entries)
		entries = append(entries, entry{ref: ref, jobs: jobs})
	}

	// Default image
	if img := extractDefaultImage(doc); img != "" {
		addImage(img, "")
	}

	// Per-job images and services
	for _, job := range doc.Jobs {
		if job.Image != "" {
			addImage(job.Image, job.Name)
		}
		for _, svc := range job.Services {
			addImage(svc, job.Name)
		}
	}

	// Build result slice with parsed components.
	result := make([]ContainerImage, 0, len(entries))
	for _, e := range entries {
		registry, name, tag, digest := parseImageRef(e.ref)
		ci := ContainerImage{
			Image:    e.ref,
			Registry: registry,
			Name:     name,
			Tag:      tag,
			Digest:   digest,
			Jobs:     e.jobs,
		}
		if ci.Jobs == nil {
			ci.Jobs = []string{}
		}
		result = append(result, ci)
	}
	return result
}

// collectIncludes converts pipeline includes into PBOM include entries.
func (g *Generator) collectIncludes(doc *pipeline.Document) []PBOMInclude {
	if len(doc.Includes) == 0 {
		return []PBOMInclude{}
	}

	result := make([]PBOMInclude, 0, len(doc.Includes))
	for _, inc := range doc.Includes {
		pi := PBOMInclude{
			Type:     string(inc.Type),
			Location: includeLocation(inc),
			Project:  inc.Project,
			Ref:      inc.Ref,
		}
		if inc.Type == pipeline.IncludeComponent {
			pi.Component = inc.Component
		}
		result = append(result, pi)
	}
	return result
}

// includeLocation returns a human-readable location string for an include,
// determined by its type.
func includeLocation(inc pipeline.Include) string {
	switch inc.Type {
	case pipeline.IncludeLocal:
		return inc.Local
	case pipeline.IncludeProject:
		// If there are files, join them; otherwise use the project path.
		if len(inc.File) > 0 {
			return strings.Join(inc.File, ", ")
		}
		return inc.Project
	case pipeline.IncludeRemote:
		return inc.Remote
	case pipeline.IncludeTemplate:
		return inc.Template
	case pipeline.IncludeComponent:
		return inc.Component
	default:
		return ""
	}
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

	// Find the tag: the last ":" that appears after the last "/".
	// A colon before the first "/" could be a registry port.
	lastSlash := strings.LastIndex(s, "/")
	colonIdx := strings.LastIndex(s, ":")
	if colonIdx > lastSlash {
		tag = s[colonIdx+1:]
		s = s[:colonIdx]
	}

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
