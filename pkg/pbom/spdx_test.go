package pbom

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToSPDX_Basic(t *testing.T) {
	p := &PBOM{
		PBOMVersion: Version,
		Project:     ProjectInfo{Path: "group/project", ID: 42, URL: "https://gitlab.com/group/project", Branch: "main"},
		ContainerImages: []ContainerImage{
			{Image: "alpine:3.18", Registry: "docker.io", Name: "alpine", Tag: "3.18", Jobs: []string{"build"}},
			{Image: "node:latest", Registry: "docker.io", Name: "node", Tag: "latest", Jobs: []string{"test"}},
			{Image: "gcr.io/proj/app@sha256:abc123", Registry: "gcr.io", Name: "proj/app", Digest: "sha256:abc123", Jobs: []string{"deploy"}},
		},
		Includes: []PBOMInclude{
			{Type: "project", Location: "templates/ci.yml", Project: "shared/templates", Ref: "v1.0"},
			{Type: "remote", Location: "https://example.com/ci.yml"},
		},
	}

	spdx := p.ToSPDX("1.0.0")

	if spdx.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %q, want SPDX-2.3", spdx.SPDXVersion)
	}
	if spdx.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %q, want CC0-1.0", spdx.DataLicense)
	}
	if !strings.HasPrefix(spdx.SPDXID, "SPDXRef-DOCUMENT") {
		t.Errorf("SPDXID = %q, want SPDXRef-DOCUMENT prefix", spdx.SPDXID)
	}
	// 3 images + 2 includes = 5 packages
	if len(spdx.Packages) != 5 {
		t.Errorf("Packages count = %d, want 5", len(spdx.Packages))
	}

	// Verify JSON serializable
	data, err := json.MarshalIndent(spdx, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON output is empty")
	}
}

func TestToSPDX_EmptyPBOM(t *testing.T) {
	p := &PBOM{
		Project: ProjectInfo{Path: "empty/project"},
	}
	spdx := p.ToSPDX("1.0.0")
	if len(spdx.Packages) != 0 {
		t.Errorf("expected 0 packages for empty PBOM, got %d", len(spdx.Packages))
	}
}

func TestToSPDX_Relationships(t *testing.T) {
	p := &PBOM{
		Project: ProjectInfo{Path: "group/project"},
		ContainerImages: []ContainerImage{
			{Image: "alpine:3.18", Name: "alpine", Tag: "3.18", Jobs: []string{"build"}},
		},
	}
	spdx := p.ToSPDX("1.0.0")
	if len(spdx.Relationships) < 1 {
		t.Error("expected at least 1 DESCRIBES relationship")
	}
	foundDescribes := false
	for _, rel := range spdx.Relationships {
		if rel.RelationshipType == "DESCRIBES" {
			foundDescribes = true
		}
	}
	if !foundDescribes {
		t.Error("no DESCRIBES relationship found")
	}
}
