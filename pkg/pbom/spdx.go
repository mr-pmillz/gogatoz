package pbom

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// SPDX represents an SPDX 2.3 Software Bill of Materials document.
type SPDX struct {
	SPDXVersion   string             `json:"spdxVersion"`
	DataLicense   string             `json:"dataLicense"`
	SPDXID        string             `json:"SPDXID"`
	Name          string             `json:"name"`
	DocumentNS    string             `json:"documentNamespace"`
	CreationInfo  SPDXCreationInfo   `json:"creationInfo"`
	Packages      []SPDXPackage      `json:"packages,omitempty"`
	Relationships []SPDXRelationship `json:"relationships,omitempty"`
}

// SPDXCreationInfo contains metadata about the BOM generation.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a single package in the SPDX document.
type SPDXPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	Version          string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
	Comment          string            `json:"comment,omitempty"`
}

// SPDXExternalRef is an external reference attached to a package.
type SPDXExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

// SPDXRelationship represents a relationship between two SPDX elements.
type SPDXRelationship struct {
	Element          string `json:"spdxElementId"`
	RelatedElement   string `json:"relatedSpdxElement"`
	RelationshipType string `json:"relationshipType"`
}

// ToSPDX converts a PBOM into an SPDX 2.3 JSON document.
// toolVersion is embedded in the creator metadata (e.g. "v1.2.3" or "dev").
func (p *PBOM) ToSPDX(toolVersion string) SPDX {
	now := time.Now().UTC()
	h := sha256.Sum256(fmt.Appendf(nil, "%s-%s", p.Project.Path, now.Format(time.RFC3339)))
	ns := fmt.Sprintf("https://gogatoz.dev/spdx/%x", h[:16])

	s := SPDX{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        fmt.Sprintf("gogatoz-pbom-%s", p.Project.Path),
		DocumentNS:  ns,
		CreationInfo: SPDXCreationInfo{
			Created:  now.Format(time.RFC3339),
			Creators: []string{fmt.Sprintf("Tool: gogatoz-%s", toolVersion)},
		},
	}

	idx := 0
	for _, img := range p.ContainerImages {
		idx++
		pkg := SPDXPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Container-%d", idx),
			Name:             img.Name,
			Version:          img.Tag,
			DownloadLocation: img.Image,
			FilesAnalyzed:    false,
		}
		purl := buildContainerPurl(img)
		if purl != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, SPDXExternalRef{
				Category: "PACKAGE-MANAGER",
				Type:     "purl",
				Locator:  purl,
			})
		}
		if len(img.Jobs) > 0 {
			pkg.Comment = fmt.Sprintf("Used by jobs: %s", strings.Join(img.Jobs, ", "))
		}
		s.Packages = append(s.Packages, pkg)
		s.Relationships = append(s.Relationships, SPDXRelationship{
			Element:          "SPDXRef-DOCUMENT",
			RelatedElement:   pkg.SPDXID,
			RelationshipType: "DESCRIBES",
		})
	}

	for _, inc := range p.Includes {
		idx++
		pkg := SPDXPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Include-%d", idx),
			Name:             inc.Location,
			FilesAnalyzed:    false,
			DownloadLocation: inc.Location,
		}
		if inc.Ref != "" {
			pkg.Version = inc.Ref
		}
		if inc.Project != "" {
			pkg.Comment = fmt.Sprintf("CI include from project: %s", inc.Project)
		}
		s.Packages = append(s.Packages, pkg)
		s.Relationships = append(s.Relationships, SPDXRelationship{
			Element:          "SPDXRef-DOCUMENT",
			RelatedElement:   pkg.SPDXID,
			RelationshipType: "DESCRIBES",
		})
	}

	return s
}
