package pbom

import (
	"crypto/sha256"
	"fmt"
)

// CycloneDXSpecVersion is the CycloneDX specification version used.
const CycloneDXSpecVersion = "1.5"

// CycloneDX represents a CycloneDX Software Bill of Materials document.
type CycloneDX struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	Version      int                  `json:"version"`
	SerialNumber string               `json:"serialNumber"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

// CycloneDXMetadata contains metadata about the BOM generation.
type CycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []CycloneDXTool `json:"tools,omitempty"`
}

// CycloneDXTool describes a tool that generated the BOM.
type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CycloneDXComponent represents a single component in the BOM.
type CycloneDXComponent struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref,omitempty"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	Purl       string              `json:"purl,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXProperty is a key-value property attached to a component.
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ToCycloneDX converts a PBOM into a CycloneDX 1.5 BOM document.
// toolVersion is embedded in the tool metadata (e.g. "v1.2.3" or "dev").
func (p *PBOM) ToCycloneDX(toolVersion string) *CycloneDX {
	cdx := &CycloneDX{
		BOMFormat:    "CycloneDX",
		SpecVersion:  CycloneDXSpecVersion,
		Version:      1,
		SerialNumber: generateSerialNumber(p.Project.Path, p.GeneratedAt.String()),
		Metadata: CycloneDXMetadata{
			Timestamp: p.GeneratedAt.Format("2006-01-02T15:04:05Z"),
			Tools: []CycloneDXTool{
				{
					Vendor:  "mr-pmillz",
					Name:    "gogatoz",
					Version: toolVersion,
				},
			},
		},
	}

	var components []CycloneDXComponent

	// Container images as "container" components.
	for i, img := range p.ContainerImages {
		comp := CycloneDXComponent{
			Type:   "container",
			BOMRef: fmt.Sprintf("container-%d", i),
			Name:   img.Name,
			Purl:   buildContainerPurl(img),
		}
		if img.Tag != "" {
			comp.Version = img.Tag
		}

		// Attach job references and registry as properties.
		var props []CycloneDXProperty
		if img.Registry != "" {
			props = append(props, CycloneDXProperty{
				Name:  "gogatoz:registry",
				Value: img.Registry,
			})
		}
		if img.Digest != "" {
			props = append(props, CycloneDXProperty{
				Name:  "gogatoz:digest",
				Value: img.Digest,
			})
		}
		for _, j := range img.Jobs {
			props = append(props, CycloneDXProperty{
				Name:  "gogatoz:job",
				Value: j,
			})
		}
		if len(props) > 0 {
			comp.Properties = props
		}

		components = append(components, comp)
	}

	// Includes as "library" components (CI configuration dependencies).
	for i, inc := range p.Includes {
		comp := CycloneDXComponent{
			Type:   "library",
			BOMRef: fmt.Sprintf("include-%d", i),
			Name:   inc.Location,
		}
		if inc.Ref != "" {
			comp.Version = inc.Ref
		}

		var props []CycloneDXProperty
		props = append(props, CycloneDXProperty{
			Name:  "gogatoz:includeType",
			Value: inc.Type,
		})
		if inc.Project != "" {
			props = append(props, CycloneDXProperty{
				Name:  "gogatoz:project",
				Value: inc.Project,
			})
		}
		if inc.Component != "" {
			props = append(props, CycloneDXProperty{
				Name:  "gogatoz:component",
				Value: inc.Component,
			})
		}
		comp.Properties = props
		components = append(components, comp)
	}

	cdx.Components = components
	return cdx
}

// buildContainerPurl creates a Package URL for a container image.
// Format: pkg:docker/name@version or pkg:docker/namespace/name@version
func buildContainerPurl(img ContainerImage) string {
	name := img.Name
	// If registry is present, include it as qualifier-style namespace.
	if img.Registry != "" {
		name = img.Registry + "/" + name
	}
	version := img.Tag
	if img.Digest != "" {
		version = img.Digest
	}
	if version != "" {
		return fmt.Sprintf("pkg:docker/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:docker/%s", name)
}

// generateSerialNumber creates a deterministic UUID-like serial number from
// the project path and timestamp. Uses SHA-256 to produce a v5-style UUID
// without requiring a UUID dependency.
func generateSerialNumber(projectPath, timestamp string) string {
	h := sha256.Sum256([]byte(projectPath + "|" + timestamp))
	// Format as UUID v5 style: xxxxxxxx-xxxx-5xxx-xxxx-xxxxxxxxxxxx
	return fmt.Sprintf("urn:uuid:%08x-%04x-5%03x-%04x-%012x",
		h[0:4],
		h[4:6],
		uint16(h[6:8][0])<<8|uint16(h[6:8][1])&0x0fff,
		uint16(h[8:10][0])<<8|uint16(h[8:10][1])&0x3fff|0x8000,
		h[10:16],
	)
}

// FormatPurl is a convenience for external callers that want to build a purl
// from separate image parts without constructing a full ContainerImage.
func FormatPurl(registry, name, tag, digest string) string {
	fullName := name
	if registry != "" {
		fullName = registry + "/" + fullName
	}
	version := tag
	if digest != "" {
		version = digest
	}
	if version != "" {
		return fmt.Sprintf("pkg:docker/%s@%s", fullName, version)
	}
	return fmt.Sprintf("pkg:docker/%s", fullName)
}

// SplitImageRef is an exported convenience wrapper around parseImageRef for
// callers outside the pbom package.
func SplitImageRef(ref string) (registry, name, tag, digest string) {
	return parseImageRef(ref)
}

