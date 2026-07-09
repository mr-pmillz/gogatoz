package pbom

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestGenerate_MultipleJobsAndImages(t *testing.T) {
	doc := &pipeline.Document{
		Raw: map[string]any{},
		Jobs: []pipeline.Job{
			{Name: "build", Image: "golang:1.22-alpine", Services: []string{"docker:dind"}},
			{Name: "test", Image: "golang:1.22-alpine"},
			{Name: "deploy", Image: "alpine:3.19"},
		},
	}

	gen := NewGenerator("group/project", 42, "https://gitlab.com/group/project", "main")
	pbom := gen.Generate(doc)

	if pbom.PBOMVersion != Version {
		t.Fatalf("PBOMVersion = %q, want %q", pbom.PBOMVersion, Version)
	}
	if pbom.Project.Path != "group/project" {
		t.Fatalf("Project.Path = %q, want %q", pbom.Project.Path, "group/project")
	}
	if pbom.Project.ID != 42 {
		t.Fatalf("Project.ID = %d, want 42", pbom.Project.ID)
	}

	// 3 unique images: golang:1.22-alpine, docker:dind, alpine:3.19
	if len(pbom.ContainerImages) != 3 {
		t.Fatalf("len(ContainerImages) = %d, want 3", len(pbom.ContainerImages))
	}

	// Total refs: build(image+service) + test(image) + deploy(image) = 4
	if pbom.Summary.TotalImages != 4 {
		t.Errorf("Summary.TotalImages = %d, want 4", pbom.Summary.TotalImages)
	}
	if pbom.Summary.UniqueImages != 3 {
		t.Errorf("Summary.UniqueImages = %d, want 3", pbom.Summary.UniqueImages)
	}
}

func TestGenerate_Includes(t *testing.T) {
	doc := &pipeline.Document{
		Raw: map[string]any{},
		Includes: []pipeline.Include{
			{Type: pipeline.IncludeLocal, Local: "/templates/ci.yml"},
			{Type: pipeline.IncludeProject, Project: "shared/templates", File: []string{"build.yml"}, Ref: "v2.0"},
			{Type: pipeline.IncludeRemote, Remote: "https://example.com/ci.yml"},
			{Type: pipeline.IncludeTemplate, Template: "Auto-DevOps.gitlab-ci.yml"},
			{Type: pipeline.IncludeComponent, Component: "gitlab.com/components/sast@1.0"},
		},
	}

	gen := NewGenerator("test/project", 1, "", "main")
	pbom := gen.Generate(doc)

	if len(pbom.Includes) != 5 {
		t.Fatalf("len(Includes) = %d, want 5", len(pbom.Includes))
	}
	if pbom.Summary.TotalIncludes != 5 {
		t.Errorf("Summary.TotalIncludes = %d, want 5", pbom.Summary.TotalIncludes)
	}

	tests := []struct {
		idx      int
		wantType string
		wantLoc  string
		wantProj string
		wantRef  string
		wantComp string
	}{
		{0, "local", "/templates/ci.yml", "", "", ""},
		{1, "project", "build.yml", "shared/templates", "v2.0", ""},
		{2, "remote", "https://example.com/ci.yml", "", "", ""},
		{3, "template", "Auto-DevOps.gitlab-ci.yml", "", "", ""},
		{4, "component", "gitlab.com/components/sast@1.0", "", "", "gitlab.com/components/sast@1.0"},
	}
	for _, tt := range tests {
		inc := pbom.Includes[tt.idx]
		if inc.Type != tt.wantType {
			t.Errorf("Includes[%d].Type = %q, want %q", tt.idx, inc.Type, tt.wantType)
		}
		if inc.Location != tt.wantLoc {
			t.Errorf("Includes[%d].Location = %q, want %q", tt.idx, inc.Location, tt.wantLoc)
		}
		if inc.Project != tt.wantProj {
			t.Errorf("Includes[%d].Project = %q, want %q", tt.idx, inc.Project, tt.wantProj)
		}
		if inc.Ref != tt.wantRef {
			t.Errorf("Includes[%d].Ref = %q, want %q", tt.idx, inc.Ref, tt.wantRef)
		}
		if inc.Component != tt.wantComp {
			t.Errorf("Includes[%d].Component = %q, want %q", tt.idx, inc.Component, tt.wantComp)
		}
	}
}

func TestGenerate_DedupSameImageTwoJobs(t *testing.T) {
	doc := &pipeline.Document{
		Raw: map[string]any{},
		Jobs: []pipeline.Job{
			{Name: "lint", Image: "golangci/golangci-lint:v1.59"},
			{Name: "vet", Image: "golangci/golangci-lint:v1.59"},
		},
	}

	gen := NewGenerator("p", 0, "", "")
	pbom := gen.Generate(doc)

	if len(pbom.ContainerImages) != 1 {
		t.Fatalf("expected 1 unique image, got %d", len(pbom.ContainerImages))
	}

	img := pbom.ContainerImages[0]
	if len(img.Jobs) != 2 {
		t.Fatalf("expected 2 job refs, got %d", len(img.Jobs))
	}
	if img.Jobs[0] != "lint" || img.Jobs[1] != "vet" {
		t.Errorf("Jobs = %v, want [lint, vet]", img.Jobs)
	}
	if pbom.Summary.TotalImages != 2 {
		t.Errorf("TotalImages = %d, want 2 (pre-dedup count)", pbom.Summary.TotalImages)
	}
	if pbom.Summary.UniqueImages != 1 {
		t.Errorf("UniqueImages = %d, want 1", pbom.Summary.UniqueImages)
	}
}

func TestGenerate_DefaultImageFromRaw(t *testing.T) {
	tests := []struct {
		name     string
		raw      map[string]any
		wantImg  string
		wantName string
	}{
		{
			name:     "string image",
			raw:      map[string]any{"image": "ruby:3.2"},
			wantImg:  "ruby:3.2",
			wantName: "ruby",
		},
		{
			name:     "map image with name key",
			raw:      map[string]any{"image": map[string]any{"name": "node:20-slim", "entrypoint": []string{""}}},
			wantImg:  "node:20-slim",
			wantName: "node",
		},
		{
			name: "no image key",
			raw:  map[string]any{"stages": []string{"build"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &pipeline.Document{Raw: tt.raw}
			gen := NewGenerator("p", 0, "", "")
			pbom := gen.Generate(doc)

			if tt.wantImg == "" {
				if len(pbom.ContainerImages) != 0 {
					t.Fatalf("expected 0 images, got %d", len(pbom.ContainerImages))
				}
				return
			}

			if len(pbom.ContainerImages) != 1 {
				t.Fatalf("expected 1 image, got %d", len(pbom.ContainerImages))
			}
			img := pbom.ContainerImages[0]
			if img.Image != tt.wantImg {
				t.Errorf("Image = %q, want %q", img.Image, tt.wantImg)
			}
			if img.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", img.Name, tt.wantName)
			}
			// Default image has no job association.
			if len(img.Jobs) != 0 {
				t.Errorf("Jobs = %v, want empty", img.Jobs)
			}
		})
	}
}

func TestGenerate_EmptyDocument(t *testing.T) {
	doc := &pipeline.Document{Raw: map[string]any{}}
	gen := NewGenerator("empty/project", 99, "", "main")
	pbom := gen.Generate(doc)

	if pbom.PBOMVersion != Version {
		t.Errorf("PBOMVersion = %q, want %q", pbom.PBOMVersion, Version)
	}
	if len(pbom.ContainerImages) != 0 {
		t.Errorf("expected 0 images, got %d", len(pbom.ContainerImages))
	}
	if len(pbom.Includes) != 0 {
		t.Errorf("expected 0 includes, got %d", len(pbom.Includes))
	}
	if pbom.Summary.TotalImages != 0 || pbom.Summary.UniqueImages != 0 || pbom.Summary.TotalIncludes != 0 {
		t.Errorf("expected all summary counts to be 0, got %+v", pbom.Summary)
	}
}

func TestGenerate_NilDocument(t *testing.T) {
	gen := NewGenerator("nil/project", 0, "", "")
	pbom := gen.Generate(nil)

	if pbom.ContainerImages == nil {
		t.Error("ContainerImages should be empty slice, not nil")
	}
	if pbom.Includes == nil {
		t.Error("Includes should be empty slice, not nil")
	}
	if len(pbom.ContainerImages) != 0 {
		t.Errorf("expected 0 images, got %d", len(pbom.ContainerImages))
	}
}

func TestToCycloneDX_BasicStructure(t *testing.T) {
	doc := &pipeline.Document{
		Raw: map[string]any{"image": "python:3.12"},
		Jobs: []pipeline.Job{
			{Name: "build", Image: "golang:1.22"},
		},
		Includes: []pipeline.Include{
			{Type: pipeline.IncludeTemplate, Template: "SAST.gitlab-ci.yml"},
		},
	}

	gen := NewGenerator("test/cdx", 10, "https://gitlab.com/test/cdx", "main")
	pbom := gen.Generate(doc)
	cdx := pbom.ToCycloneDX("v1.0.0")

	if cdx.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want CycloneDX", cdx.BOMFormat)
	}
	if cdx.SpecVersion != "1.5" {
		t.Errorf("SpecVersion = %q, want 1.5", cdx.SpecVersion)
	}
	if cdx.Version != 1 {
		t.Errorf("Version = %d, want 1", cdx.Version)
	}
	if !strings.HasPrefix(cdx.SerialNumber, "urn:uuid:") {
		t.Errorf("SerialNumber = %q, want urn:uuid: prefix", cdx.SerialNumber)
	}

	// Tool metadata
	if len(cdx.Metadata.Tools) != 1 {
		t.Fatalf("len(Tools) = %d, want 1", len(cdx.Metadata.Tools))
	}
	tool := cdx.Metadata.Tools[0]
	if tool.Vendor != "mr-pmillz" || tool.Name != "gogatoz" || tool.Version != "v1.0.0" {
		t.Errorf("Tool = %+v, want vendor=mr-pmillz name=gogatoz version=v1.0.0", tool)
	}

	// 2 container images + 1 include = 3 components
	if len(cdx.Components) != 3 {
		t.Fatalf("len(Components) = %d, want 3", len(cdx.Components))
	}

	// First two are containers, third is library (include).
	if cdx.Components[0].Type != "container" {
		t.Errorf("Components[0].Type = %q, want container", cdx.Components[0].Type)
	}
	if cdx.Components[1].Type != "container" {
		t.Errorf("Components[1].Type = %q, want container", cdx.Components[1].Type)
	}
	if cdx.Components[2].Type != "library" {
		t.Errorf("Components[2].Type = %q, want library", cdx.Components[2].Type)
	}
}

func TestToCycloneDX_ContainerPurl(t *testing.T) {
	tests := []struct {
		name     string
		image    ContainerImage
		wantPurl string
	}{
		{
			name:     "simple image with tag",
			image:    ContainerImage{Name: "golang", Tag: "1.22"},
			wantPurl: "pkg:docker/golang@1.22",
		},
		{
			name:     "image with registry",
			image:    ContainerImage{Registry: "gcr.io", Name: "my-project/app", Tag: "v1.0"},
			wantPurl: "pkg:docker/gcr.io/my-project/app@v1.0",
		},
		{
			name:     "image with digest",
			image:    ContainerImage{Name: "alpine", Digest: "sha256:abc123"},
			wantPurl: "pkg:docker/alpine@sha256:abc123",
		},
		{
			name:     "digest takes precedence over tag",
			image:    ContainerImage{Name: "node", Tag: "20", Digest: "sha256:def456"},
			wantPurl: "pkg:docker/node@sha256:def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildContainerPurl(tt.image)
			if got != tt.wantPurl {
				t.Errorf("buildContainerPurl() = %q, want %q", got, tt.wantPurl)
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		ref        string
		wantReg    string
		wantName   string
		wantTag    string
		wantDigest string
	}{
		{"alpine", "", "alpine", "latest", ""},
		{"golang:1.22", "", "golang", "1.22", ""},
		{"gcr.io/proj/app:v1", "gcr.io", "proj/app", "v1", ""},
		{"localhost/myimg:dev", "localhost", "myimg", "dev", ""},
		{"registry:5000/img:tag", "registry:5000", "img", "tag", ""},
		{"alpine@sha256:abc123", "", "alpine", "", "sha256:abc123"},
		{"golang:1.22@sha256:deadbeef", "", "golang", "1.22", "sha256:deadbeef"},
		{"library/nginx", "", "library/nginx", "latest", ""},
		{"", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			reg, name, tag, digest := parseImageRef(tt.ref)
			if reg != tt.wantReg {
				t.Errorf("registry = %q, want %q", reg, tt.wantReg)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", tag, tt.wantTag)
			}
			if digest != tt.wantDigest {
				t.Errorf("digest = %q, want %q", digest, tt.wantDigest)
			}
		})
	}
}

func TestGenerate_ServicesTrackedToJobs(t *testing.T) {
	doc := &pipeline.Document{
		Raw: map[string]any{},
		Jobs: []pipeline.Job{
			{
				Name:     "integration",
				Image:    "golang:1.22",
				Services: []string{"postgres:15", "redis:7"},
			},
		},
	}

	gen := NewGenerator("svc/test", 0, "", "")
	pbom := gen.Generate(doc)

	// 3 unique images: golang:1.22, postgres:15, redis:7
	if len(pbom.ContainerImages) != 3 {
		t.Fatalf("expected 3 images, got %d", len(pbom.ContainerImages))
	}

	// All three should reference the "integration" job.
	for _, img := range pbom.ContainerImages {
		if len(img.Jobs) != 1 || img.Jobs[0] != "integration" {
			t.Errorf("image %q: Jobs = %v, want [integration]", img.Image, img.Jobs)
		}
	}
}

func TestGenerate_DefaultImageDedupWithJob(t *testing.T) {
	// Default image is the same as a job image — should dedup to one entry.
	doc := &pipeline.Document{
		Raw: map[string]any{"image": "golang:1.22"},
		Jobs: []pipeline.Job{
			{Name: "build", Image: "golang:1.22"},
		},
	}

	gen := NewGenerator("dedup/test", 0, "", "")
	pbom := gen.Generate(doc)

	if len(pbom.ContainerImages) != 1 {
		t.Fatalf("expected 1 unique image, got %d", len(pbom.ContainerImages))
	}

	img := pbom.ContainerImages[0]
	// The default image was added first (no job), then the job was merged.
	if len(img.Jobs) != 1 || img.Jobs[0] != "build" {
		t.Errorf("Jobs = %v, want [build]", img.Jobs)
	}
}

func TestGenerateSerialNumber_Deterministic(t *testing.T) {
	a := generateSerialNumber("proj", "2024-01-01")
	b := generateSerialNumber("proj", "2024-01-01")
	if a != b {
		t.Errorf("serial numbers differ for same input: %q vs %q", a, b)
	}

	c := generateSerialNumber("proj", "2024-01-02")
	if a == c {
		t.Errorf("serial numbers should differ for different timestamps")
	}

	if !strings.HasPrefix(a, "urn:uuid:") {
		t.Errorf("serial number should start with urn:uuid:, got %q", a)
	}
}

func TestIncludeLocation(t *testing.T) {
	tests := []struct {
		name    string
		include pipeline.Include
		want    string
	}{
		{
			name:    "local",
			include: pipeline.Include{Type: pipeline.IncludeLocal, Local: "/ci/build.yml"},
			want:    "/ci/build.yml",
		},
		{
			name:    "project with files",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "shared/ci", File: []string{"a.yml", "b.yml"}},
			want:    "a.yml, b.yml",
		},
		{
			name:    "project without files",
			include: pipeline.Include{Type: pipeline.IncludeProject, Project: "shared/ci"},
			want:    "shared/ci",
		},
		{
			name:    "remote",
			include: pipeline.Include{Type: pipeline.IncludeRemote, Remote: "https://example.com/ci.yml"},
			want:    "https://example.com/ci.yml",
		},
		{
			name:    "template",
			include: pipeline.Include{Type: pipeline.IncludeTemplate, Template: "SAST.gitlab-ci.yml"},
			want:    "SAST.gitlab-ci.yml",
		},
		{
			name:    "component",
			include: pipeline.Include{Type: pipeline.IncludeComponent, Component: "gitlab.com/comp/sast@1.0"},
			want:    "gitlab.com/comp/sast@1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := includeLocation(tt.include)
			if got != tt.want {
				t.Errorf("includeLocation() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitImageRef_Exported(t *testing.T) {
	reg, name, tag, digest := SplitImageRef("gcr.io/proj/app:v1.0@sha256:abc")
	if reg != "gcr.io" {
		t.Errorf("registry = %q, want gcr.io", reg)
	}
	if name != "proj/app" {
		t.Errorf("name = %q, want proj/app", name)
	}
	if tag != "v1.0" {
		t.Errorf("tag = %q, want v1.0", tag)
	}
	if digest != "sha256:abc" {
		t.Errorf("digest = %q, want sha256:abc", digest)
	}
}

func TestFormatPurl(t *testing.T) {
	tests := []struct {
		reg, name, tag, digest string
		want                   string
	}{
		{"", "alpine", "3.19", "", "pkg:docker/alpine@3.19"},
		{"gcr.io", "proj/app", "v1", "", "pkg:docker/gcr.io/proj/app@v1"},
		{"", "node", "", "sha256:abc", "pkg:docker/node@sha256:abc"},
		{"", "scratch", "", "", "pkg:docker/scratch"},
	}
	for _, tt := range tests {
		got := FormatPurl(tt.reg, tt.name, tt.tag, tt.digest)
		if got != tt.want {
			t.Errorf("FormatPurl(%q,%q,%q,%q) = %q, want %q", tt.reg, tt.name, tt.tag, tt.digest, got, tt.want)
		}
	}
}
