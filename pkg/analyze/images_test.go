package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		input                  string
		wantRegistry, wantName string
		wantTag, wantDigest    string
	}{
		{"golang:1.22-alpine", "", "golang", "1.22-alpine", ""},
		{"python:latest", "", "python", "latest", ""},
		{"ubuntu", "", "ubuntu", "latest", ""},
		{"nginx:dev", "", "nginx", "dev", ""},
		{"golang:1.22@sha256:abc123", "", "golang", "1.22", "sha256:abc123"},
		{"python:3.12", "", "python", "3.12", ""},
		{"docker.io/library/python:3.12", "docker.io", "library/python", "3.12", ""},
		{"registry.example.com/myapp@sha256:abc123", "registry.example.com", "myapp", "", "sha256:abc123"},
		{"registry.example.com:5000/myapp:v2.1.0", "registry.example.com:5000", "myapp", "v2.1.0", ""},
		{"myorg/myimage", "", "myorg/myimage", "latest", ""},
		{"docker:dind", "", "docker", "dind", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			reg, name, tag, digest := parseImageRef(tc.input)
			if reg != tc.wantRegistry {
				t.Errorf("registry: got %q, want %q", reg, tc.wantRegistry)
			}
			if name != tc.wantName {
				t.Errorf("name: got %q, want %q", name, tc.wantName)
			}
			if tag != tc.wantTag {
				t.Errorf("tag: got %q, want %q", tag, tc.wantTag)
			}
			if digest != tc.wantDigest {
				t.Errorf("digest: got %q, want %q", digest, tc.wantDigest)
			}
		})
	}
}

func TestIsMutableTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"latest", true},
		{"dev", true},
		{"master", true},
		{"main", true},
		{"nightly", true},
		{"edge", true},
		{"canary", true},
		{"unstable", true},
		{"beta", true},
		{"alpha", true},
		{"rc", true},
		{"staging", true},
		{"LATEST", true},  // case-insensitive
		{"Latest", true},  // case-insensitive
		{"v1", true},      // major-only version tag
		{"v12", true},     // major-only version tag
		{"v1.2.3", false}, // fully qualified version
		{"v1-alpine", false},
		{"1.22-alpine", false},
		{"3.12", false},
		{"dind", false},
		{"alpine", false},
		{"slim", false},
	}

	for _, tc := range tests {
		t.Run(tc.tag, func(t *testing.T) {
			got := isMutableTag(tc.tag)
			if got != tc.want {
				t.Errorf("isMutableTag(%q) = %v, want %v", tc.tag, got, tc.want)
			}
		})
	}
}

func TestDetectImageIssues(t *testing.T) {
	tests := []struct {
		name            string
		doc             *pipeline.Document
		wantMutableTag  bool
		wantNotPinned   bool
		mutableTagCount int
		notPinnedCount  int
	}{
		{
			name: "specific version tag — no IMAGE_MUTABLE_TAG",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "build",
					Image: "golang:1.22-alpine",
				}},
			},
			wantMutableTag: false,
			wantNotPinned:  true,
			notPinnedCount: 1,
		},
		{
			name: "python:latest — IMAGE_MUTABLE_TAG",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "test",
					Image: "python:latest",
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
		{
			name: "ubuntu no tag — implicit latest — IMAGE_MUTABLE_TAG",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "test",
					Image: "ubuntu",
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
		{
			name: "nginx:dev — IMAGE_MUTABLE_TAG",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "serve",
					Image: "nginx:dev",
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
		{
			name: "digest-pinned image — no IMAGE_MUTABLE_TAG, no IMAGE_NOT_PINNED",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "build",
					Image: "golang:1.22@sha256:abc123",
				}},
			},
			wantMutableTag: false,
			wantNotPinned:  false,
		},
		{
			name: "python:3.12 — IMAGE_NOT_PINNED only",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "lint",
					Image: "python:3.12",
				}},
			},
			wantMutableTag: false,
			wantNotPinned:  true,
			notPinnedCount: 1,
		},
		{
			name: "variable reference — skip both checks",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "deploy",
					Image: "$CI_REGISTRY/myapp:$CI_COMMIT_SHA",
				}},
			},
			wantMutableTag: false,
			wantNotPinned:  false,
		},
		{
			name: "default image ruby:latest — IMAGE_MUTABLE_TAG",
			doc: &pipeline.Document{
				Raw: map[string]any{"image": "ruby:latest"},
				Jobs: []pipeline.Job{{
					Name: "test",
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
		{
			name: "service docker:dind — not mutable",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:     "build",
					Image:    "docker:24.0@sha256:deadbeef",
					Services: []string{"docker:dind"},
				}},
			},
			wantMutableTag: false,
			wantNotPinned:  true, // docker:dind is not pinned
			notPinnedCount: 1,
		},
		{
			name: "service postgres:latest — IMAGE_MUTABLE_TAG",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:     "test",
					Image:    "golang:1.22@sha256:abc123",
					Services: []string{"postgres:latest"},
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
		{
			name:           "nil document — no findings",
			doc:            nil,
			wantMutableTag: false,
			wantNotPinned:  false,
		},
		{
			name: "v1 tag — mutable (major-only)",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "build",
					Image: "node:v1",
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
		{
			name: "v1.2.3 tag — not mutable",
			doc: &pipeline.Document{
				Raw: map[string]any{},
				Jobs: []pipeline.Job{{
					Name:  "build",
					Image: "node:v1.2.3",
				}},
			},
			wantMutableTag: false,
			wantNotPinned:  true,
			notPinnedCount: 1,
		},
		{
			name: "default image as mapping with name",
			doc: &pipeline.Document{
				Raw: map[string]any{
					"image": map[string]any{"name": "python:latest"},
				},
				Jobs: []pipeline.Job{{
					Name: "test",
				}},
			},
			wantMutableTag:  true,
			wantNotPinned:   true,
			mutableTagCount: 1,
			notPinnedCount:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := detectImageIssues(tc.doc, nil)

			gotMutable := hasFindingID(findings, ImageMutableTagID)
			if gotMutable != tc.wantMutableTag {
				t.Errorf("IMAGE_MUTABLE_TAG: got %v, want %v; findings=%+v", gotMutable, tc.wantMutableTag, findings)
			}

			gotNotPinned := hasFindingID(findings, ImageNotPinnedID)
			if gotNotPinned != tc.wantNotPinned {
				t.Errorf("IMAGE_NOT_PINNED: got %v, want %v; findings=%+v", gotNotPinned, tc.wantNotPinned, findings)
			}

			if tc.mutableTagCount > 0 {
				count := countFindingID(findings, ImageMutableTagID)
				if count != tc.mutableTagCount {
					t.Errorf("IMAGE_MUTABLE_TAG count: got %d, want %d", count, tc.mutableTagCount)
				}
			}

			if tc.notPinnedCount > 0 {
				count := countFindingID(findings, ImageNotPinnedID)
				if count != tc.notPinnedCount {
					t.Errorf("IMAGE_NOT_PINNED count: got %d, want %d", count, tc.notPinnedCount)
				}
			}
		})
	}
}

// countFindingID returns how many findings have the given ID.
func countFindingID(fs []Finding, id string) int {
	n := 0
	for _, f := range fs {
		if f.ID == id {
			n++
		}
	}
	return n
}
