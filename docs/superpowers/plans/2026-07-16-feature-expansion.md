# Feature Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 6 new analysis capabilities to GoGatoZ: Pages analysis, SBOM/SPDX extension, variable inheritance analysis, environment/deployment analysis, CI config drift detection, and group-level security dashboard.

**Architecture:** Each feature follows the existing pattern: detection functions in `pkg/analyze/`, data collection in `pkg/enumerate/`, CLI wiring in `cmd/`, report rendering in `pkg/enumerate/report/`. Two features (drift, dashboard) add new Cobra subcommands. All integrate into the existing finding/report pipeline.

**Tech Stack:** Go 1.24.4, Cobra CLI, PTerm terminal rendering, GORM/SQLite persistence, GitLab SDK (`gitlab.com/gitlab-org/api/client-go`), embedded HTML templates with Bootstrap 5 + Chart.js.

## Global Constraints

- Module path: `github.com/mr-pmillz/gogatoz`
- All finding IDs use `UPPER_SNAKE_CASE` string constants
- Every finding needs entries in 3 registries: `findingCodeRegistry` (codes.go), `taxonomyRegistry` (taxonomy.go), `steps` table (analyze.go)
- Detection functions signature: `func detect*(doc *pipeline.Document) []Finding` (or with extra args wrapped in closure)
- Table-driven tests with `t.Run()` subtests
- Run `go build ./...` and `go test -race ./...` after every code change
- PTerm writing: use `Srender()`/`Sprint()` then `fmt.Fprintln(w, s)` — never `Render()` directly
- golangci-lint v2 config: gocognit threshold 30, gosec (excluding G306)
- Commit messages: lowercase, no trailing period, conventional commits format

---

### Task 1: GitLab Pages CI/CD Analysis (Feature 19)

Pure YAML analysis — no API calls needed. Detects Pages deployment jobs and flags security risks.

**Files:**
- Create: `pkg/analyze/pages.go`
- Create: `pkg/analyze/pages_test.go`
- Modify: `pkg/analyze/codes.go` — add 3 finding registry entries
- Modify: `pkg/analyze/taxonomy.go` — add 3 taxonomy entries
- Modify: `pkg/analyze/analyze.go` — add step to `steps` table

**Interfaces:**
- Consumes: `pipeline.Document` (existing), `pipeline.Job` (existing — uses `Name`, `Stage`, `Artifacts`, `Rules`, `Environment` fields)
- Produces: `detectPagesRisks(doc *pipeline.Document) []Finding` — called by the `steps` table in `analyze.Run()`

- [ ] **Step 1: Write the failing test for Pages detection**

Create `pkg/analyze/pages_test.go`:

```go
package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectPagesRisks(t *testing.T) {
	tests := []struct {
		name     string
		doc      *pipeline.Document
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "pages_job_with_mr_trigger",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "pages",
					Stage: "deploy",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/"},
					},
					Rules: []any{
						map[string]any{"if": `$CI_MERGE_REQUEST_IID`},
					},
				}},
			},
			wantIDs: []string{PagesMRDeployRiskID},
		},
		{
			name: "pages_job_with_sensitive_paths",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "pages",
					Stage: "deploy",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/", "coverage/", "docs/api/"},
					},
				}},
			},
			wantIDs: []string{PagesSensitivePathID},
		},
		{
			name: "pages_job_public_deploy",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "pages",
					Stage: "deploy",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/"},
					},
				}},
			},
			wantIDs: []string{PagesPublicDeployID},
		},
		{
			name: "non_pages_job_no_findings",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Stage:  "build",
					Script: []string{"go build"},
				}},
			},
			wantNone: true,
		},
		{
			name: "nil_doc_no_findings",
			doc:      nil,
			wantNone: true,
		},
		{
			name: "pages_stage_detected",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:  "deploy_docs",
					Stage: "pages",
					Script: []string{"echo deploy"},
					Artifacts: map[string]any{
						"paths": []any{"public/"},
					},
				}},
			},
			wantIDs: []string{PagesPublicDeployID},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPagesRisks(tt.doc)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(got), got)
				}
				return
			}
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range got {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s, got %v", wantID, findingIDs(got))
				}
			}
		})
	}
}

func findingIDs(fs []Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.ID
	}
	return ids
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/phil/projects/gogatoz && go test -run TestDetectPagesRisks ./pkg/analyze/ -v`
Expected: FAIL — `PagesMRDeployRiskID` undefined, `detectPagesRisks` undefined

- [ ] **Step 3: Implement Pages detection**

Create `pkg/analyze/pages.go`:

```go
package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	PagesPublicDeployID  = "PAGES_PUBLIC_DEPLOY"
	PagesMRDeployRiskID  = "PAGES_MR_DEPLOY_RISK"
	PagesSensitivePathID = "PAGES_SENSITIVE_PATH"
)

var pagesSensitivePatterns = []string{
	"coverage/", "docs/api/", "docs/internal/", "storybook/",
	".env", "config/", "swagger/", "openapi/",
}

func isPagesJob(job pipeline.Job) bool {
	if strings.EqualFold(job.Name, "pages") {
		return true
	}
	if strings.EqualFold(job.Stage, "pages") {
		return true
	}
	paths := artifactPaths(job)
	for _, p := range paths {
		if strings.HasPrefix(p, "public/") || p == "public" {
			if strings.EqualFold(job.Stage, "deploy") || strings.EqualFold(job.Name, "pages") {
				return true
			}
		}
	}
	return false
}

func artifactPaths(job pipeline.Job) []string {
	if job.Artifacts == nil {
		return nil
	}
	raw, ok := job.Artifacts["paths"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	var paths []string
	for _, v := range list {
		if s, ok := v.(string); ok {
			paths = append(paths, s)
		}
	}
	return paths
}

func detectPagesRisks(doc *pipeline.Document) []Finding {
	if doc == nil {
		return nil
	}
	var findings []Finding
	for _, job := range doc.Jobs {
		if !isPagesJob(job) {
			continue
		}

		if jobHasMRTrigger(job) {
			findings = append(findings, Finding{
				ID:          PagesMRDeployRiskID,
				Severity:    SeverityHigh,
				Title:       "Pages job can be triggered from MR pipelines",
				Description: "A GitLab Pages job runs on merge request pipelines, allowing content injection via MR. An attacker can deploy arbitrary content to the project's Pages URL.",
				Evidence:    fmt.Sprintf("job=%s has MR trigger rules", job.Name),
				JobName:     job.Name,
			})
		}

		paths := artifactPaths(job)
		var matched []string
		for _, p := range paths {
			for _, pat := range pagesSensitivePatterns {
				if strings.Contains(strings.ToLower(p), pat) {
					matched = append(matched, p)
					break
				}
			}
		}
		if len(matched) > 0 {
			findings = append(findings, Finding{
				ID:          PagesSensitivePathID,
				Severity:    SeverityMedium,
				Title:       "Pages artifacts include potentially sensitive paths",
				Description: "Pages deployment includes paths that commonly contain sensitive information such as coverage reports, API documentation, or configuration files.",
				Evidence:    fmt.Sprintf("job=%s sensitive_paths=%s", job.Name, strings.Join(matched, ", ")),
				JobName:     job.Name,
			})
		}

		findings = append(findings, Finding{
			ID:          PagesPublicDeployID,
			Severity:    SeverityMedium,
			Title:       "GitLab Pages deployment detected",
			Description: "A Pages job deploys static content. Verify that published content is intended to be public and does not expose internal documentation, credentials, or sensitive data.",
			Evidence:    fmt.Sprintf("job=%s stage=%s", job.Name, job.Stage),
			JobName:     job.Name,
		})
	}
	return findings
}

func jobHasMRTrigger(job pipeline.Job) bool {
	rules, ok := job.Rules.([]any)
	if !ok {
		return false
	}
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		ifClause, _ := rm["if"].(string)
		lower := strings.ToLower(ifClause)
		if strings.Contains(lower, "ci_merge_request") || strings.Contains(lower, "merge_request_event") {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Register finding codes in codes.go**

Add to `findingCodeRegistry` in `pkg/analyze/codes.go` (after the last entry, before the closing `}`):

```go
	PagesPublicDeployID: {
		ID:          PagesPublicDeployID,
		Severity:    SeverityMedium,
		Title:       "GitLab Pages deployment detected",
		Description: "A Pages job deploys static content that may expose internal documentation, credentials, or sensitive data publicly.",
		Remediation: "Enable Pages access control, review published content, and restrict Pages deployment to protected branches only. See: https://docs.gitlab.com/ee/user/project/pages/pages_access_control.html",
	},
	PagesMRDeployRiskID: {
		ID:          PagesMRDeployRiskID,
		Severity:    SeverityHigh,
		Title:       "Pages job can be triggered from MR pipelines",
		Description: "A GitLab Pages job runs on merge request pipelines, allowing content injection via MR. An attacker can deploy arbitrary content to the project's Pages URL.",
		Remediation: "Restrict Pages deployment jobs to protected branches only using rules:if with $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH. See: https://docs.gitlab.com/ee/user/project/pages/",
	},
	PagesSensitivePathID: {
		ID:          PagesSensitivePathID,
		Severity:    SeverityMedium,
		Title:       "Pages artifacts include potentially sensitive paths",
		Description: "Pages deployment includes paths that commonly contain sensitive information such as coverage reports, API documentation, or configuration files.",
		Remediation: "Review Pages artifact paths and exclude directories containing sensitive information (coverage/, docs/api/, config/). Use .gitlab/pages/ or public/ with curated content only.",
	},
```

- [ ] **Step 5: Register taxonomy entries in taxonomy.go**

Add CWE/ATT&CK/OWASP constants if not already present, then add to `taxonomyRegistry` in `pkg/analyze/taxonomy.go`:

```go
	// --- Pages risks ---
	PagesPublicDeployID: {
		CWEs:          []CWERef{cwe538},
		ATTACKRefs:    []ATTACKRef{{ID: "T1530", Name: "Data from Cloud Storage Object"}},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},
	PagesMRDeployRiskID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3},
	},
	PagesSensitivePathID: {
		CWEs:          []CWERef{cwe538},
		ATTACKRefs:    []ATTACKRef{{ID: "T1530", Name: "Data from Cloud Storage Object"}},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},
```

Note: `cwe538` (CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory) is already declared. ATT&CK T1530 may need declaring as a new constant:

```go
	attackT1530 = ATTACKRef{ID: "T1530", Name: "Data from Cloud Storage Object"}
```

- [ ] **Step 6: Register in steps table in analyze.go**

Add to the `steps` slice in `Run()` in `pkg/analyze/analyze.go`, after the last entry:

```go
		{"pages_risks", detectPagesRisks},
```

- [ ] **Step 7: Build and test**

Run: `cd /home/phil/projects/gogatoz && go build ./... && go test -race ./pkg/analyze/ -v`
Expected: All tests pass including TestDetectPagesRisks

- [ ] **Step 8: Commit**

```bash
git add pkg/analyze/pages.go pkg/analyze/pages_test.go pkg/analyze/codes.go pkg/analyze/taxonomy.go pkg/analyze/analyze.go
git commit -m "feat: add GitLab Pages CI/CD security analysis (feature 19)"
```

---

### Task 2: SBOM SPDX Extension (Feature 22)

Extends `pkg/pbom/` with SPDX 2.3 JSON output and adds `spdx` format option to the `pbom` command. Also adds two new analyzer rules for unpinned images and missing digests.

**Files:**
- Create: `pkg/pbom/spdx.go`
- Create: `pkg/pbom/spdx_test.go`
- Create: `pkg/analyze/sbom.go`
- Create: `pkg/analyze/sbom_test.go`
- Modify: `cmd/pbom.go` — add `spdx` format
- Modify: `pkg/analyze/codes.go` — add 2 finding registry entries
- Modify: `pkg/analyze/taxonomy.go` — add 2 taxonomy entries
- Modify: `pkg/analyze/analyze.go` — add step to `steps` table

**Interfaces:**
- Consumes: `pbom.PBOM` struct (existing — `ContainerImages []ContainerImage`, `Includes []PBOMInclude`)
- Produces: `func (p *PBOM) ToSPDX(toolVersion string) SPDX` — SPDX 2.3 JSON struct
- Produces: `detectSBOMIssues(doc *pipeline.Document) []Finding` — analyzer rule

- [ ] **Step 1: Write the failing test for SPDX output**

Create `pkg/pbom/spdx_test.go`:

```go
package pbom

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToSPDX_Basic(t *testing.T) {
	p := &PBOM{
		PBOMVersion: SchemaVersion,
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/phil/projects/gogatoz && go test -run TestToSPDX ./pkg/pbom/ -v`
Expected: FAIL — `ToSPDX` method undefined

- [ ] **Step 3: Implement SPDX output**

Create `pkg/pbom/spdx.go`:

```go
package pbom

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

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

type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	Version          string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
	Comment          string            `json:"comment,omitempty"`
}

type SPDXExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type SPDXRelationship struct {
	Element          string `json:"spdxElementId"`
	RelatedElement   string `json:"relatedSpdxElement"`
	RelationshipType string `json:"relationshipType"`
}

func (p *PBOM) ToSPDX(toolVersion string) SPDX {
	now := time.Now().UTC()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%s", p.Project.Path, now.Format(time.RFC3339))))
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
```

- [ ] **Step 4: Add spdx format to cmd/pbom.go**

In `cmd/pbom.go`, find the output format switch and add the `spdx` case. The existing code has a switch like:

```go
switch strings.ToLower(pbomFormat) {
case "cyclonedx", "cdx":
    // ...CycloneDX output...
default:
    // ...native JSON output...
}
```

Add a `case "spdx":` branch:

```go
case "spdx":
    spdxDoc := bom.ToSPDX(version)
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    if err := enc.Encode(spdxDoc); err != nil {
        return fmt.Errorf("encode SPDX: %w", err)
    }
```

- [ ] **Step 5: Write failing test for SBOM analyzer rules**

Create `pkg/analyze/sbom_test.go`:

```go
package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectSBOMIssues(t *testing.T) {
	tests := []struct {
		name     string
		doc      *pipeline.Document
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "image_with_latest_tag",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "node:latest",
					Script: []string{"npm test"},
				}},
			},
			wantIDs: []string{SBOMUnpinnedImageID},
		},
		{
			name: "image_with_no_tag",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "python",
					Script: []string{"pytest"},
				}},
			},
			wantIDs: []string{SBOMUnpinnedImageID},
		},
		{
			name: "image_pinned_with_digest",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "alpine@sha256:abc123def456",
					Script: []string{"echo ok"},
				}},
			},
			wantNone: true,
		},
		{
			name: "image_with_version_no_digest",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Image:  "node:18.20",
					Script: []string{"npm test"},
				}},
			},
			wantIDs: []string{SBOMNoDigestID},
		},
		{
			name: "nil_doc",
			doc:      nil,
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSBOMIssues(tt.doc)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(got), findingIDs(got))
				}
				return
			}
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range got {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s, got %v", wantID, findingIDs(got))
				}
			}
		})
	}
}
```

- [ ] **Step 6: Implement SBOM analyzer rules**

Create `pkg/analyze/sbom.go`:

```go
package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	SBOMUnpinnedImageID = "SBOM_UNPINNED_IMAGE"
	SBOMNoDigestID      = "SBOM_NO_DIGEST"
)

func detectSBOMIssues(doc *pipeline.Document) []Finding {
	if doc == nil {
		return nil
	}
	var findings []Finding
	seen := map[string]bool{}

	checkImage := func(image, jobName string) {
		image = strings.TrimSpace(image)
		if image == "" {
			return
		}
		if seen[image] {
			return
		}
		seen[image] = true

		hasDigest := strings.Contains(image, "@sha256:")
		if hasDigest {
			return
		}

		parts := strings.SplitN(image, ":", 2)
		tag := ""
		if len(parts) == 2 {
			tag = parts[1]
		}

		if tag == "" || strings.EqualFold(tag, "latest") {
			findings = append(findings, Finding{
				ID:          SBOMUnpinnedImageID,
				Severity:    SeverityMedium,
				Title:       "Container image uses mutable or missing tag",
				Description: "A container image uses ':latest' or has no tag specified. This means the image content can change without notice, creating a supply chain risk.",
				Evidence:    fmt.Sprintf("image=%s job=%s", image, jobName),
				JobName:     jobName,
			})
			return
		}

		findings = append(findings, Finding{
			ID:          SBOMNoDigestID,
			Severity:    SeverityLow,
			Title:       "Container image not pinned by digest",
			Description: "A container image uses a version tag but is not pinned by digest (@sha256:...). Tags are mutable and can be overwritten, compromising reproducibility.",
			Evidence:    fmt.Sprintf("image=%s job=%s", image, jobName),
			JobName:     jobName,
		})
	}

	for _, job := range doc.Jobs {
		checkImage(job.Image, job.Name)
		for _, svc := range job.Services {
			checkImage(svc, job.Name)
		}
	}

	return findings
}
```

- [ ] **Step 7: Register SBOM findings in codes.go and taxonomy.go**

Add to `findingCodeRegistry` in `pkg/analyze/codes.go`:

```go
	SBOMUnpinnedImageID: {
		ID:          SBOMUnpinnedImageID,
		Severity:    SeverityMedium,
		Title:       "Container image uses mutable or missing tag",
		Description: "A container image uses ':latest' or has no tag specified, creating a supply chain risk.",
		Remediation: "Pin container images to specific version tags or digests. Use image@sha256:... for maximum reproducibility.",
	},
	SBOMNoDigestID: {
		ID:          SBOMNoDigestID,
		Severity:    SeverityLow,
		Title:       "Container image not pinned by digest",
		Description: "A container image uses a version tag but is not pinned by digest (@sha256:...). Tags are mutable.",
		Remediation: "Pin images by digest (image@sha256:...) for fully reproducible builds. See: https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
	},
```

Add to `taxonomyRegistry` in `pkg/analyze/taxonomy.go`:

```go
	// --- SBOM / Supply chain pinning ---
	SBOMUnpinnedImageID: {
		CWEs:          []CWERef{cwe829},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9},
	},
	SBOMNoDigestID: {
		CWEs:          []CWERef{cwe345},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec9},
	},
```

- [ ] **Step 8: Register in steps table**

Add to the `steps` slice in `analyze.go`:

```go
		{"sbom_issues", detectSBOMIssues},
```

- [ ] **Step 9: Build and test**

Run: `cd /home/phil/projects/gogatoz && go build ./... && go test -race ./pkg/analyze/ ./pkg/pbom/ -v`
Expected: All tests pass

- [ ] **Step 10: Commit**

```bash
git add pkg/pbom/spdx.go pkg/pbom/spdx_test.go pkg/analyze/sbom.go pkg/analyze/sbom_test.go cmd/pbom.go pkg/analyze/codes.go pkg/analyze/taxonomy.go pkg/analyze/analyze.go
git commit -m "feat: add SPDX 2.3 output and SBOM analyzer rules (feature 22)"
```

---

### Task 3: CI/CD Variables Inheritance Analysis (Feature 28)

Adds API-driven variable metadata collection during enumeration and analyzer rules for variable inheritance risks.

**Files:**
- Create: `pkg/enumerate/variables.go`
- Create: `pkg/enumerate/variables_test.go`
- Create: `pkg/analyze/varinherit.go`
- Create: `pkg/analyze/varinherit_test.go`
- Modify: `pkg/enumerate/enumerator.go` — add `VariableInfo` fields to `Result`, `FetchVariables` to `Options`, wire into `scanOne()`
- Modify: `pkg/analyze/codes.go` — add 4 finding registry entries
- Modify: `pkg/analyze/taxonomy.go` — add 4 taxonomy entries
- Modify: `pkg/analyze/analyze.go` — add step (closure captures variable data)
- Modify: `cmd/enumerate.go` — add `--fetch-variables` flag

**Interfaces:**
- Consumes: `gitlabx.Client` (existing), `gitlab.ProjectVariables.ListVariables`, `gitlab.GroupVariables.ListVariables`
- Produces: `VariableInfo` struct, `FetchProjectVariables(ctx, cl, projectID) ([]VariableInfo, error)`, `FetchGroupVariables(ctx, cl, groupID) ([]VariableInfo, error)`
- Produces: `detectVariableInheritanceRisk(doc *pipeline.Document, projectVars, groupVars []VariableInfo) []Finding`

- [ ] **Step 1: Write the failing test for variable fetching**

Create `pkg/enumerate/variables_test.go`:

```go
package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestFetchProjectVariables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/1/variables" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "20")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "2")
			vars := []map[string]any{
				{"key": "DB_PASSWORD", "protected": true, "masked": true, "environment_scope": "*", "variable_type": "env_var"},
				{"key": "DEBUG_FLAG", "protected": false, "masked": false, "environment_scope": "*", "variable_type": "env_var"},
			}
			json.NewEncoder(w).Encode(vars)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	vars, err := FetchProjectVariables(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("FetchProjectVariables: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(vars))
	}
	if vars[0].Key != "DB_PASSWORD" || !vars[0].Protected || !vars[0].Masked {
		t.Errorf("var[0] mismatch: %+v", vars[0])
	}
	if vars[1].Key != "DEBUG_FLAG" || vars[1].Protected || vars[1].Masked {
		t.Errorf("var[1] mismatch: %+v", vars[1])
	}
	for _, v := range vars {
		if v.Source != "project" {
			t.Errorf("expected source=project, got %s", v.Source)
		}
	}
}

func TestFetchGroupVariables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/groups/10/variables" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "20")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "1")
			vars := []map[string]any{
				{"key": "GROUP_TOKEN", "protected": true, "masked": true, "environment_scope": "*", "variable_type": "env_var"},
			}
			json.NewEncoder(w).Encode(vars)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	vars, err := FetchGroupVariables(context.Background(), cl, 10)
	if err != nil {
		t.Fatalf("FetchGroupVariables: %v", err)
	}
	if len(vars) != 1 {
		t.Fatalf("expected 1 var, got %d", len(vars))
	}
	if vars[0].Source != "group" {
		t.Errorf("expected source=group, got %s", vars[0].Source)
	}
}

func TestFetchProjectVariables_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "20")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "0")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	cl, _ := gitlabx.New(srv.URL, "tok")
	vars, err := FetchProjectVariables(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 0 {
		t.Errorf("expected 0 vars, got %d", len(vars))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/phil/projects/gogatoz && go test -run TestFetchProjectVariables ./pkg/enumerate/ -v`
Expected: FAIL — `FetchProjectVariables` undefined

- [ ] **Step 3: Implement variable fetching**

Create `pkg/enumerate/variables.go`:

```go
package enumerate

import (
	"context"
	"log/slog"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type VariableInfo struct {
	Key              string `json:"key"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	EnvironmentScope string `json:"environment_scope"`
	Source           string `json:"source"`
}

func FetchProjectVariables(ctx context.Context, cl *gitlabx.Client, projectID any) ([]VariableInfo, error) {
	slog.Debug("fetching project variables", "project_id", projectID)
	var all []VariableInfo
	page := int64(1)
	for {
		vars, resp, err := cl.GL.ProjectVariables.ListVariables(projectID,
			&gitlab.ListProjectVariablesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}},
			gitlab.WithContext(ctx))
		if err != nil {
			return all, err
		}
		for _, v := range vars {
			all = append(all, VariableInfo{
				Key:              v.Key,
				Protected:        v.Protected,
				Masked:           v.Masked,
				EnvironmentScope: v.EnvironmentScope,
				Source:           "project",
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	slog.Debug("fetched project variables", "project_id", projectID, "count", len(all))
	return all, nil
}

func FetchGroupVariables(ctx context.Context, cl *gitlabx.Client, groupID any) ([]VariableInfo, error) {
	slog.Debug("fetching group variables", "group_id", groupID)
	var all []VariableInfo
	page := int64(1)
	for {
		vars, resp, err := cl.GL.GroupVariables.ListVariables(groupID,
			&gitlab.ListGroupVariablesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}},
			gitlab.WithContext(ctx))
		if err != nil {
			return all, err
		}
		for _, v := range vars {
			all = append(all, VariableInfo{
				Key:              v.Key,
				Protected:        v.Protected,
				Masked:           v.Masked,
				EnvironmentScope: v.EnvironmentScope,
				Source:           "group",
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	slog.Debug("fetched group variables", "group_id", groupID, "count", len(all))
	return all, nil
}
```

- [ ] **Step 4: Write the failing test for variable inheritance analysis**

Create `pkg/analyze/varinherit_test.go`:

```go
package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectVariableInheritanceRisk(t *testing.T) {
	tests := []struct {
		name        string
		doc         *pipeline.Document
		projectVars []enumerate.VariableInfo
		groupVars   []enumerate.VariableInfo
		wantIDs     []string
		wantNone    bool
	}{
		{
			name: "yaml_shadows_protected_project_var",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:      "build",
					Script:    []string{"echo $DB_PASSWORD"},
					Variables: map[string]any{"DB_PASSWORD": "hardcoded"},
				}},
			},
			projectVars: []enumerate.VariableInfo{
				{Key: "DB_PASSWORD", Protected: true, Masked: true, Source: "project"},
			},
			wantIDs: []string{VarInheritanceShadowID},
		},
		{
			name: "unmasked_secret_pattern",
			doc:  &pipeline.Document{},
			projectVars: []enumerate.VariableInfo{
				{Key: "API_TOKEN", Protected: true, Masked: false, Source: "project"},
			},
			wantIDs: []string{VarUnmaskedSecretID},
		},
		{
			name: "unprotected_masked_secret",
			doc:  &pipeline.Document{},
			projectVars: []enumerate.VariableInfo{
				{Key: "DEPLOY_KEY", Protected: false, Masked: true, Source: "project"},
			},
			wantIDs: []string{VarUnprotectedSecretID},
		},
		{
			name: "mr_override_risk",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "deploy",
					Script: []string{"curl -H \"Authorization: $API_KEY\" https://api.example.com"},
					Rules:  []any{map[string]any{"if": "$CI_MERGE_REQUEST_IID"}},
				}},
			},
			projectVars: []enumerate.VariableInfo{
				{Key: "API_KEY", Protected: false, Masked: true, Source: "project"},
			},
			wantIDs: []string{VarMROverrideRiskID},
		},
		{
			name: "properly_protected_and_masked",
			doc:  &pipeline.Document{},
			projectVars: []enumerate.VariableInfo{
				{Key: "SAFE_TOKEN", Protected: true, Masked: true, Source: "project"},
			},
			wantNone: true,
		},
		{
			name:     "nil_doc_no_vars",
			doc:      nil,
			wantNone: true,
		},
		{
			name:     "no_vars",
			doc:      &pipeline.Document{},
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectVariableInheritanceRisk(tt.doc, tt.projectVars, tt.groupVars)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(got), findingIDs(got))
				}
				return
			}
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range got {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s, got %v", wantID, findingIDs(got))
				}
			}
		})
	}
}
```

- [ ] **Step 5: Implement variable inheritance analysis**

Create `pkg/analyze/varinherit.go`:

```go
package analyze

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	VarInheritanceShadowID = "VAR_INHERITANCE_SHADOW"
	VarUnmaskedSecretID    = "VAR_UNMASKED_SECRET"
	VarUnprotectedSecretID = "VAR_UNPROTECTED_SECRET"
	VarMROverrideRiskID    = "VAR_MR_OVERRIDE_RISK"
)

var secretKeyPatterns = []string{
	"TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL", "APIKEY",
	"API_KEY", "PRIVATE", "AUTH", "PASSPHRASE",
}

func looksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)
	for _, pat := range secretKeyPatterns {
		if strings.Contains(upper, pat) {
			return true
		}
	}
	return false
}

func detectVariableInheritanceRisk(doc *pipeline.Document, projectVars, groupVars []enumerate.VariableInfo) []Finding {
	var findings []Finding
	allAPIVars := append(projectVars, groupVars...)

	if len(allAPIVars) == 0 {
		return nil
	}

	apiVarMap := map[string]enumerate.VariableInfo{}
	for _, v := range allAPIVars {
		apiVarMap[v.Key] = v
	}

	for _, v := range allAPIVars {
		if looksLikeSecret(v.Key) && !v.Masked {
			findings = append(findings, Finding{
				ID:          VarUnmaskedSecretID,
				Severity:    SeverityHigh,
				Title:       "CI/CD variable with secret-like name is not masked",
				Description: "A project or group CI/CD variable whose name suggests it holds a secret is not configured with masked=true. The value will be visible in job logs.",
				Evidence:    fmt.Sprintf("key=%s source=%s masked=false", v.Key, v.Source),
			})
		}

		if v.Masked && !v.Protected {
			findings = append(findings, Finding{
				ID:          VarUnprotectedSecretID,
				Severity:    SeverityHigh,
				Title:       "Masked CI/CD variable is not protected",
				Description: "A masked variable is accessible from unprotected branches and MR pipelines. An attacker with MR access can exfiltrate the value via artifact-based or network-based methods.",
				Evidence:    fmt.Sprintf("key=%s source=%s masked=true protected=false", v.Key, v.Source),
			})
		}
	}

	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		for varKey := range job.Variables {
			if apiVar, ok := apiVarMap[varKey]; ok && apiVar.Protected {
				findings = append(findings, Finding{
					ID:          VarInheritanceShadowID,
					Severity:    SeverityMedium,
					Title:       "Job variable shadows a protected CI/CD variable",
					Description: "A job-level variable defined in .gitlab-ci.yml shadows a protected project or group variable. The YAML value takes precedence, bypassing the protected variable's security controls.",
					Evidence:    fmt.Sprintf("key=%s job=%s shadows %s-level protected variable", varKey, job.Name, apiVar.Source),
					JobName:     job.Name,
				})
			}
		}

		if !jobHasMRTrigger(job) {
			continue
		}
		scripts := effectiveScripts(job, doc)
		for _, line := range scripts {
			for varKey, apiVar := range apiVarMap {
				if apiVar.Protected {
					continue
				}
				ref := "$" + varKey
				refBraced := "${" + varKey + "}"
				if strings.Contains(line, ref) || strings.Contains(line, refBraced) {
					findings = append(findings, Finding{
						ID:          VarMROverrideRiskID,
						Severity:    SeverityMedium,
						Title:       "MR pipeline can override unprotected variable used in script",
						Description: "A CI/CD variable referenced in a script is not protected. An MR pipeline can override it with a malicious value, potentially injecting commands or altering behavior.",
						Evidence:    fmt.Sprintf("key=%s job=%s source=%s used in script", varKey, job.Name, apiVar.Source),
						JobName:     job.Name,
					})
					break
				}
			}
		}
	}

	return findings
}
```

- [ ] **Step 6: Register finding codes in codes.go**

Add to `findingCodeRegistry`:

```go
	VarInheritanceShadowID: {
		ID:          VarInheritanceShadowID,
		Severity:    SeverityMedium,
		Title:       "Job variable shadows a protected CI/CD variable",
		Description: "A job-level YAML variable shadows a protected project or group CI/CD variable, bypassing protection controls.",
		Remediation: "Remove the job-level variable override or ensure it does not conflict with protected variables. Use variable inheritance intentionally.",
	},
	VarUnmaskedSecretID: {
		ID:          VarUnmaskedSecretID,
		Severity:    SeverityHigh,
		Title:       "CI/CD variable with secret-like name is not masked",
		Description: "A variable whose name suggests it holds a secret is not masked. The value will be visible in job logs.",
		Remediation: "Enable masking on CI/CD variables that hold secrets (Settings > CI/CD > Variables > Masked). See: https://docs.gitlab.com/ee/ci/variables/#mask-a-cicd-variable",
	},
	VarUnprotectedSecretID: {
		ID:          VarUnprotectedSecretID,
		Severity:    SeverityHigh,
		Title:       "Masked CI/CD variable is not protected",
		Description: "A masked variable is accessible from unprotected branches and MR pipelines, enabling exfiltration.",
		Remediation: "Enable protection on masked variables so they are only available on protected branches. See: https://docs.gitlab.com/ee/ci/variables/#protect-a-cicd-variable",
	},
	VarMROverrideRiskID: {
		ID:          VarMROverrideRiskID,
		Severity:    SeverityMedium,
		Title:       "MR pipeline can override unprotected variable used in script",
		Description: "An unprotected CI/CD variable is referenced in a script that runs on MR pipelines. An attacker can override it via MR pipeline variables.",
		Remediation: "Protect variables referenced in security-sensitive scripts or restrict MR pipeline access to those scripts.",
	},
```

- [ ] **Step 7: Register taxonomy entries in taxonomy.go**

Add to `taxonomyRegistry`:

```go
	// --- Variable inheritance risks ---
	VarInheritanceShadowID: {
		CWEs:          []CWERef{{ID: 807, Name: "Reliance on Untrusted Inputs in a Security Decision"}},
		ATTACKRefs:    []ATTACKRef{attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},
	VarUnmaskedSecretID: {
		CWEs:          []CWERef{cwe312},
		ATTACKRefs:    []ATTACKRef{{ID: "T1552.001", Name: "Unsecured Credentials: Credentials In Files"}},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec2},
	},
	VarUnprotectedSecretID: {
		CWEs:          []CWERef{{ID: 668, Name: "Exposure of Resource to Wrong Sphere"}},
		ATTACKRefs:    []ATTACKRef{{ID: "T1552.001", Name: "Unsecured Credentials: Credentials In Files"}},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec2},
	},
	VarMROverrideRiskID: {
		CWEs:          []CWERef{{ID: 807, Name: "Reliance on Untrusted Inputs in a Security Decision"}},
		ATTACKRefs:    []ATTACKRef{attackT1574},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec4},
	},
```

Note: Some CWE constants (807, 668) may need declaring in the `var` block. Check if `cwe807` and `cwe668` exist; if not, add:

```go
	cwe668 = CWERef{ID: 668, Name: "Exposure of Resource to Wrong Sphere"}
	cwe807 = CWERef{ID: 807, Name: "Reliance on Untrusted Inputs in a Security Decision"}
```

- [ ] **Step 8: Wire into enumerate pipeline**

In `pkg/enumerate/enumerator.go`:

Add fields to `Result`:
```go
	ProjectVariables []VariableInfo `json:"project_variables,omitempty"`
	GroupVariables   []VariableInfo `json:"group_variables,omitempty"`
```

Add field to `Options`:
```go
	FetchVariables bool
```

In `scanOne()`, after the protected branches / runners section and before CI file fetch, add:

```go
	var projectVars, groupVars []VariableInfo
	if opts.FetchVariables {
		if pv, err := FetchProjectVariables(ctx, cl, proj.ID); err == nil {
			projectVars = pv
			r.ProjectVariables = pv
		} else {
			appendError(&r, fmt.Sprintf("project variables: %v", err))
		}
		if proj.Namespace != nil && proj.Namespace.ID != 0 {
			if gv, err := FetchGroupVariables(ctx, cl, proj.Namespace.ID); err == nil {
				groupVars = gv
				r.GroupVariables = gv
			} else {
				appendError(&r, fmt.Sprintf("group variables: %v", err))
			}
		}
	}
```

Then pass `projectVars` and `groupVars` to the analyzer. Since `analyze.Run()` uses a step table, and variable inheritance detection needs API data (not just the pipeline document), add a new `Option` to `analyze`:

In `pkg/analyze/analyze.go`, add:
```go
type VariableData struct {
	ProjectVars []enumerate.VariableInfo
	GroupVars   []enumerate.VariableInfo
}

func WithVariableData(data *VariableData) Option {
	return func(c *runConfig) { c.variableData = data }
}
```

Add `variableData *VariableData` to `runConfig`.

In the steps table, add a closure:
```go
		{"variable_inheritance", func(d *pipeline.Document) []Finding {
			if cfg.variableData == nil {
				return nil
			}
			return detectVariableInheritanceRisk(d, cfg.variableData.ProjectVars, cfg.variableData.GroupVars)
		}},
```

In `scanOne()`, when building `aopts`, add:
```go
	if opts.FetchVariables && (len(projectVars) > 0 || len(groupVars) > 0) {
		aopts = append(aopts, analyze.WithVariableData(&analyze.VariableData{
			ProjectVars: projectVars,
			GroupVars:   groupVars,
		}))
	}
```

Note: This creates a circular import (`analyze` imports `enumerate.VariableInfo`). To avoid this, move `VariableInfo` to a shared location. The simplest approach: define it in `pkg/analyze/varinherit.go` and have `enumerate/variables.go` return `[]analyze.VariableInfo` instead. Alternatively, define it in `pkg/models/` or keep it in enumerate and have analyze accept a generic struct. The cleanest approach is to define `VariableInfo` in the analyze package since it's the consumer:

Move the `VariableInfo` type to `pkg/analyze/varinherit.go` and have `enumerate/variables.go` import and return `[]analyze.VariableInfo`.

- [ ] **Step 9: Add CLI flag**

In `cmd/enumerate.go`, add flag variable:
```go
	enumFetchVariables bool
```

In `init()`, add:
```go
	enumerateCmd.Flags().BoolVar(&enumFetchVariables, "fetch-variables", false, "Fetch project and group CI/CD variable metadata (requires api scope)")
```

In the options mapping section, add:
```go
	opts.FetchVariables = enumFetchVariables
```

- [ ] **Step 10: Build and test**

Run: `cd /home/phil/projects/gogatoz && go build ./... && go test -race ./pkg/analyze/ ./pkg/enumerate/ -v`
Expected: All tests pass

- [ ] **Step 11: Commit**

```bash
git add pkg/enumerate/variables.go pkg/enumerate/variables_test.go pkg/analyze/varinherit.go pkg/analyze/varinherit_test.go pkg/enumerate/enumerator.go pkg/analyze/analyze.go pkg/analyze/codes.go pkg/analyze/taxonomy.go cmd/enumerate.go
git commit -m "feat: add CI/CD variable inheritance analysis (feature 28)"
```

---

### Task 4: Environments/Deployments Analysis (Feature 25)

Fetches GitLab environment configs via API and checks deployment protection rules.

**Files:**
- Create: `pkg/enumerate/environments.go`
- Create: `pkg/enumerate/environments_test.go`
- Create: `pkg/analyze/environment.go`
- Create: `pkg/analyze/environment_test.go`
- Modify: `pkg/enumerate/enumerator.go` — add `EnvironmentInfo` fields to `Result`, `FetchEnvironments` to `Options`, wire into `scanOne()`
- Modify: `pkg/analyze/codes.go` — add 4 finding registry entries
- Modify: `pkg/analyze/taxonomy.go` — add 4 taxonomy entries
- Modify: `pkg/analyze/analyze.go` — add step and `WithEnvironmentData` option
- Modify: `cmd/enumerate.go` — add `--fetch-environments` flag

**Interfaces:**
- Consumes: `gitlabx.Client`, `gitlab.Environments.ListEnvironments`
- Produces: `EnvironmentInfo` struct (in analyze package to avoid circular imports), `FetchEnvironments(ctx, cl, projectID) ([]EnvironmentInfo, error)`
- Produces: `detectEnvironmentRisks(doc *pipeline.Document, envs []EnvironmentInfo) []Finding`

- [ ] **Step 1: Write the failing test for environment fetching**

Create `pkg/enumerate/environments_test.go`:

```go
package enumerate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestFetchEnvironments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/1/environments" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "20")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "2")
			envs := []map[string]any{
				{"id": 1, "name": "production", "tier": "production", "state": "available", "external_url": "https://prod.example.com"},
				{"id": 2, "name": "staging", "tier": "staging", "state": "available"},
			}
			json.NewEncoder(w).Encode(envs)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	envs, err := FetchEnvironments(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("FetchEnvironments: %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 envs, got %d", len(envs))
	}
	if envs[0].Name != "production" || envs[0].Tier != "production" {
		t.Errorf("env[0] mismatch: %+v", envs[0])
	}
}

func TestFetchEnvironments_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "20")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "0")
		json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer srv.Close()

	cl, _ := gitlabx.New(srv.URL, "tok")
	envs, err := FetchEnvironments(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(envs) != 0 {
		t.Errorf("expected 0 envs, got %d", len(envs))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/phil/projects/gogatoz && go test -run TestFetchEnvironments ./pkg/enumerate/ -v`
Expected: FAIL — `FetchEnvironments` undefined

- [ ] **Step 3: Implement environment fetching**

Create `pkg/enumerate/environments.go`:

```go
package enumerate

import (
	"context"
	"log/slog"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func FetchEnvironments(ctx context.Context, cl *gitlabx.Client, projectID any) ([]analyze.EnvironmentInfo, error) {
	slog.Debug("fetching environments", "project_id", projectID)
	var all []analyze.EnvironmentInfo
	page := int64(1)
	for {
		envs, resp, err := cl.GL.Environments.ListEnvironments(projectID,
			&gitlab.ListEnvironmentsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}},
			gitlab.WithContext(ctx))
		if err != nil {
			return all, err
		}
		for _, e := range envs {
			info := analyze.EnvironmentInfo{
				ID:    int64(e.ID),
				Name:  e.Name,
				State: e.State,
			}
			if e.Tier != "" {
				info.Tier = e.Tier
			}
			if e.ExternalURL != "" {
				info.ExternalURL = e.ExternalURL
			}
			if e.LastDeployment != nil {
				t := e.LastDeployment.CreatedAt
				info.LastDeployedAt = t
			}
			all = append(all, info)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	slog.Debug("fetched environments", "project_id", projectID, "count", len(all))
	return all, nil
}
```

- [ ] **Step 4: Write failing test for environment analysis**

Create `pkg/analyze/environment_test.go`:

```go
package analyze

import (
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectEnvironmentRisks(t *testing.T) {
	now := time.Now()
	stale := now.Add(-100 * 24 * time.Hour) // 100 days ago

	tests := []struct {
		name     string
		doc      *pipeline.Document
		envs     []EnvironmentInfo
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "unprotected_production_deploy",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:        "deploy",
					Environment: "production",
					Script:      []string{"deploy.sh"},
				}},
			},
			envs: []EnvironmentInfo{
				{Name: "production", Tier: "production", RequiredApprovalCount: 0},
			},
			wantIDs: []string{EnvUnprotectedDeployID, EnvNoApprovalGateID},
		},
		{
			name: "mr_triggered_deploy",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:        "deploy",
					Environment: "staging",
					Script:      []string{"deploy.sh"},
					Rules:       []any{map[string]any{"if": "$CI_MERGE_REQUEST_IID"}},
				}},
			},
			envs: []EnvironmentInfo{
				{Name: "staging", Tier: "staging"},
			},
			wantIDs: []string{EnvMRDeployRiskID},
		},
		{
			name: "stale_environment",
			doc:  &pipeline.Document{},
			envs: []EnvironmentInfo{
				{Name: "old-staging", Tier: "staging", State: "available", LastDeployedAt: &stale},
			},
			wantIDs: []string{EnvStaleDeploymentID},
		},
		{
			name:     "nil_doc",
			doc:      nil,
			envs:     []EnvironmentInfo{{Name: "prod"}},
			wantIDs:  []string{},
			wantNone: false,
		},
		{
			name:     "no_envs",
			doc:      &pipeline.Document{},
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectEnvironmentRisks(tt.doc, tt.envs)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(got), findingIDs(got))
				}
				return
			}
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range got {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s, got %v", wantID, findingIDs(got))
				}
			}
		})
	}
}
```

- [ ] **Step 5: Implement environment analysis**

Create `pkg/analyze/environment.go`:

```go
package analyze

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	EnvUnprotectedDeployID = "ENV_UNPROTECTED_DEPLOY"
	EnvNoApprovalGateID    = "ENV_NO_APPROVAL_GATE"
	EnvMRDeployRiskID      = "ENV_MR_DEPLOY_RISK"
	EnvStaleDeploymentID   = "ENV_STALE_DEPLOYMENT"
)

type EnvironmentInfo struct {
	ID                    int64      `json:"id"`
	Name                  string     `json:"name"`
	Tier                  string     `json:"tier"`
	ExternalURL           string     `json:"external_url,omitempty"`
	State                 string     `json:"state"`
	RequiredApprovalCount int        `json:"required_approval_count"`
	ProtectedBranches     []string   `json:"protected_branches,omitempty"`
	LastDeployedAt        *time.Time `json:"last_deployed_at,omitempty"`
}

const staleDays = 90

func detectEnvironmentRisks(doc *pipeline.Document, envs []EnvironmentInfo) []Finding {
	if len(envs) == 0 {
		return nil
	}

	var findings []Finding
	envMap := map[string]EnvironmentInfo{}
	for _, e := range envs {
		envMap[strings.ToLower(e.Name)] = e
	}

	for _, e := range envs {
		isProd := strings.EqualFold(e.Tier, "production")
		if isProd && e.RequiredApprovalCount == 0 {
			findings = append(findings, Finding{
				ID:          EnvNoApprovalGateID,
				Severity:    SeverityMedium,
				Title:       "Production environment lacks required approvals",
				Description: "A production-tier environment has no required approval count. Any pipeline reaching the deployment stage can deploy without human review.",
				Evidence:    fmt.Sprintf("environment=%s tier=%s approvals=0", e.Name, e.Tier),
			})
		}

		if e.State == "available" && e.LastDeployedAt != nil {
			daysSince := int(time.Since(*e.LastDeployedAt).Hours() / 24)
			if daysSince > staleDays {
				findings = append(findings, Finding{
					ID:          EnvStaleDeploymentID,
					Severity:    SeverityLow,
					Title:       "Stale environment with no recent deployments",
					Description: "An active environment has not had a deployment in over 90 days. This may represent an abandoned attack surface with outdated code.",
					Evidence:    fmt.Sprintf("environment=%s last_deploy=%dd_ago state=%s", e.Name, daysSince, e.State),
				})
			}
		}
	}

	if doc == nil {
		return findings
	}

	for _, job := range doc.Jobs {
		if job.Environment == "" {
			continue
		}
		envName := strings.ToLower(job.Environment)
		env, exists := envMap[envName]

		if exists && len(env.ProtectedBranches) == 0 && env.RequiredApprovalCount == 0 {
			findings = append(findings, Finding{
				ID:          EnvUnprotectedDeployID,
				Severity:    SeverityHigh,
				Title:       "Job deploys to unprotected environment",
				Description: "A CI job deploys to an environment that has no protection rules (no branch restrictions, no approval requirements).",
				Evidence:    fmt.Sprintf("job=%s environment=%s tier=%s", job.Name, env.Name, env.Tier),
				JobName:     job.Name,
			})
		}

		if jobHasMRTrigger(job) {
			findings = append(findings, Finding{
				ID:          EnvMRDeployRiskID,
				Severity:    SeverityHigh,
				Title:       "MR-triggered job deploys to environment",
				Description: "A job that runs on merge request pipelines deploys to an environment. An attacker can trigger deployments via MR without proper authorization.",
				Evidence:    fmt.Sprintf("job=%s environment=%s has_mr_trigger=true", job.Name, job.Environment),
				JobName:     job.Name,
			})
		}
	}

	return findings
}
```

- [ ] **Step 6: Register findings and taxonomy**

Add to `findingCodeRegistry` in `codes.go`:
```go
	EnvUnprotectedDeployID: {
		ID:          EnvUnprotectedDeployID,
		Severity:    SeverityHigh,
		Title:       "Job deploys to unprotected environment",
		Description: "A CI job deploys to an environment with no protection rules.",
		Remediation: "Configure environment protection rules: require approvals, restrict to protected branches. See: https://docs.gitlab.com/ee/ci/environments/protected_environments.html",
	},
	EnvNoApprovalGateID: {
		ID:          EnvNoApprovalGateID,
		Severity:    SeverityMedium,
		Title:       "Production environment lacks required approvals",
		Description: "A production-tier environment has zero required approvals for deployment.",
		Remediation: "Set required_approval_count > 0 for production environments. See: https://docs.gitlab.com/ee/ci/environments/deployment_approvals.html",
	},
	EnvMRDeployRiskID: {
		ID:          EnvMRDeployRiskID,
		Severity:    SeverityHigh,
		Title:       "MR-triggered job deploys to environment",
		Description: "A merge request pipeline can trigger deployment to an environment without proper authorization.",
		Remediation: "Restrict deployment jobs to protected branches only and configure environment protection rules.",
	},
	EnvStaleDeploymentID: {
		ID:          EnvStaleDeploymentID,
		Severity:    SeverityLow,
		Title:       "Stale environment with no recent deployments",
		Description: "An environment has not been deployed to in over 90 days, potentially running outdated code.",
		Remediation: "Review stale environments and either update deployments or stop/delete unused environments.",
	},
```

Add to `taxonomyRegistry` in `taxonomy.go`:
```go
	// --- Environment/deployment risks ---
	EnvUnprotectedDeployID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec5},
	},
	EnvNoApprovalGateID: {
		CWEs:          []CWERef{{ID: 862, Name: "Missing Authorization"}},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec5},
	},
	EnvMRDeployRiskID: {
		CWEs:          []CWERef{cwe284},
		ATTACKRefs:    []ATTACKRef{attackT1195_002},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec3},
	},
	EnvStaleDeploymentID: {
		CWEs:          []CWERef{{ID: 1188, Name: "Initialization with Hard-Coded Network Resource Configuration Data"}},
		ATTACKRefs:    []ATTACKRef{{ID: "T1190", Name: "Exploit Public-Facing Application"}},
		OWASPCICDRefs: []OWASPCICDRef{owaspSec7},
	},
```

- [ ] **Step 7: Wire into enumerate pipeline and add CLI flag**

Follow the same pattern as Task 3: add `WithEnvironmentData` option to analyze, `FetchEnvironments` to Options, `Environments` field to Result, environment fetch block in `scanOne()`, and `--fetch-environments` flag in `cmd/enumerate.go`.

In `pkg/analyze/analyze.go`:
```go
func WithEnvironmentData(envs []EnvironmentInfo) Option {
	return func(c *runConfig) { c.environmentData = envs }
}
```
Add `environmentData []EnvironmentInfo` to `runConfig`.

In `steps` table:
```go
		{"environment_risks", func(d *pipeline.Document) []Finding {
			return detectEnvironmentRisks(d, cfg.environmentData)
		}},
```

In `cmd/enumerate.go`:
```go
	enumFetchEnvironments bool
	// in init():
	enumerateCmd.Flags().BoolVar(&enumFetchEnvironments, "fetch-environments", false, "Fetch GitLab environment protection rules")
	// in options mapping:
	opts.FetchEnvironments = enumFetchEnvironments
```

- [ ] **Step 8: Build and test**

Run: `cd /home/phil/projects/gogatoz && go build ./... && go test -race ./pkg/analyze/ ./pkg/enumerate/ -v`
Expected: All tests pass

- [ ] **Step 9: Commit**

```bash
git add pkg/enumerate/environments.go pkg/enumerate/environments_test.go pkg/analyze/environment.go pkg/analyze/environment_test.go pkg/enumerate/enumerator.go pkg/analyze/analyze.go pkg/analyze/codes.go pkg/analyze/taxonomy.go cmd/enumerate.go
git commit -m "feat: add GitLab environments/deployments analysis (feature 25)"
```

---

### Task 5: CI/CD Config Drift Detection (Feature 24)

New `gogatoz drift` subcommand with structural diff engine, security impact assessment, and baseline storage.

**Files:**
- Create: `pkg/drift/differ.go`
- Create: `pkg/drift/differ_test.go`
- Create: `pkg/drift/security.go`
- Create: `pkg/drift/security_test.go`
- Create: `pkg/drift/baseline.go`
- Create: `pkg/drift/baseline_test.go`
- Create: `cmd/drift.go`
- Modify: `pkg/store/models.go` — add `ConfigBaseline` model

**Interfaces:**
- Consumes: `pipeline.Document` (two instances — baseline and current)
- Produces: `DriftReport` struct, `Diff(baseline, current *pipeline.Document) DriftReport`, `AssessSecurityImpact(changes []Change) []SecurityChange`
- Produces: `SaveBaseline(db *gorm.DB, ...) error`, `LoadBaseline(db *gorm.DB, projectID int64) (*ConfigBaseline, error)`

- [ ] **Step 1: Write the failing test for structural diff**

Create `pkg/drift/differ_test.go`:

```go
package drift

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDiff_AddedJob(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Stage: "build", Script: []string{"make build"}}},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "build", Stage: "build", Script: []string{"make build"}},
			{Name: "deploy", Stage: "deploy", Script: []string{"deploy.sh"}},
		},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeAdded && c.Category == CategoryJob && c.Name == "deploy" {
			found = true
		}
	}
	if !found {
		t.Error("expected added job 'deploy' in changes")
	}
}

func TestDiff_RemovedJob(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "build", Stage: "build", Script: []string{"make build"}},
			{Name: "sast", Stage: "test", Script: []string{"sast-scan"}},
		},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{
			{Name: "build", Stage: "build", Script: []string{"make build"}},
		},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeRemoved && c.Category == CategoryJob && c.Name == "sast" {
			found = true
		}
	}
	if !found {
		t.Error("expected removed job 'sast' in changes")
	}
}

func TestDiff_ModifiedScript(t *testing.T) {
	baseline := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Script: []string{"make build"}}},
	}
	current := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Script: []string{"make build", "curl http://evil.com"}}},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeModified && c.Category == CategoryScript && c.Name == "build" {
			found = true
		}
	}
	if !found {
		t.Error("expected modified script for job 'build'")
	}
}

func TestDiff_AddedInclude(t *testing.T) {
	baseline := &pipeline.Document{
		Includes: []pipeline.Include{},
	}
	current := &pipeline.Document{
		Includes: []pipeline.Include{{Remote: "https://evil.com/ci.yml"}},
	}
	report := Diff(baseline, current)
	found := false
	for _, c := range report.Changes {
		if c.Type == ChangeAdded && c.Category == CategoryInclude {
			found = true
		}
	}
	if !found {
		t.Error("expected added include in changes")
	}
}

func TestDiff_NoChanges(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{Name: "build", Script: []string{"make build"}}},
	}
	report := Diff(doc, doc)
	if len(report.Changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(report.Changes))
	}
}

func TestDiff_NilDocuments(t *testing.T) {
	report := Diff(nil, nil)
	if len(report.Changes) != 0 {
		t.Errorf("expected 0 changes for nil docs, got %d", len(report.Changes))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/phil/projects/gogatoz && go test -run TestDiff ./pkg/drift/ -v`
Expected: FAIL — package not found

- [ ] **Step 3: Implement structural diff engine**

Create `pkg/drift/differ.go`:

```go
package drift

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"

	CategoryJob      = "job"
	CategoryVariable = "variable"
	CategoryInclude  = "include"
	CategoryStage    = "stage"
	CategoryScript   = "script"
	CategoryRule     = "rule"
)

type Change struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Name     string `json:"name"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type DriftReport struct {
	ProjectPath    string           `json:"project_path,omitempty"`
	CurrentRef     string           `json:"current_ref,omitempty"`
	BaselineRef    string           `json:"baseline_ref,omitempty"`
	Timestamp      time.Time        `json:"timestamp"`
	Changes        []Change         `json:"changes"`
	SecurityImpact []SecurityChange `json:"security_impact,omitempty"`
}

func Diff(baseline, current *pipeline.Document) DriftReport {
	report := DriftReport{Timestamp: time.Now()}
	if baseline == nil && current == nil {
		return report
	}
	if baseline == nil {
		baseline = &pipeline.Document{}
	}
	if current == nil {
		current = &pipeline.Document{}
	}

	report.Changes = append(report.Changes, diffJobs(baseline, current)...)
	report.Changes = append(report.Changes, diffIncludes(baseline, current)...)
	report.Changes = append(report.Changes, diffVariables(baseline, current)...)
	report.Changes = append(report.Changes, diffStages(baseline, current)...)

	return report
}

func diffJobs(baseline, current *pipeline.Document) []Change {
	var changes []Change
	baseJobs := map[string]pipeline.Job{}
	for _, j := range baseline.Jobs {
		baseJobs[j.Name] = j
	}
	curJobs := map[string]pipeline.Job{}
	for _, j := range current.Jobs {
		curJobs[j.Name] = j
	}

	for name := range curJobs {
		if _, ok := baseJobs[name]; !ok {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryJob, Name: name})
		}
	}
	for name := range baseJobs {
		if _, ok := curJobs[name]; !ok {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryJob, Name: name})
		}
	}
	for name, curJob := range curJobs {
		baseJob, ok := baseJobs[name]
		if !ok {
			continue
		}
		oldScript := strings.Join(baseJob.Script, "\n")
		newScript := strings.Join(curJob.Script, "\n")
		if oldScript != newScript {
			changes = append(changes, Change{
				Type:     ChangeModified,
				Category: CategoryScript,
				Name:     name,
				OldValue: oldScript,
				NewValue: newScript,
			})
		}
		if baseJob.Image != curJob.Image {
			changes = append(changes, Change{
				Type:     ChangeModified,
				Category: CategoryJob,
				Name:     name,
				Detail:   fmt.Sprintf("image changed: %s -> %s", baseJob.Image, curJob.Image),
			})
		}
	}
	return changes
}

func diffIncludes(baseline, current *pipeline.Document) []Change {
	var changes []Change
	baseSet := map[string]bool{}
	for _, inc := range baseline.Includes {
		baseSet[includeKey(inc)] = true
	}
	curSet := map[string]bool{}
	for _, inc := range current.Includes {
		curSet[includeKey(inc)] = true
	}
	for _, inc := range current.Includes {
		if !baseSet[includeKey(inc)] {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryInclude, Name: includeKey(inc)})
		}
	}
	for _, inc := range baseline.Includes {
		if !curSet[includeKey(inc)] {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryInclude, Name: includeKey(inc)})
		}
	}
	return changes
}

func includeKey(inc pipeline.Include) string {
	if inc.Remote != "" {
		return "remote:" + inc.Remote
	}
	if inc.Project != "" {
		return fmt.Sprintf("project:%s/%s", inc.Project, inc.File)
	}
	if inc.Local != "" {
		return "local:" + inc.Local
	}
	if inc.Template != "" {
		return "template:" + inc.Template
	}
	if inc.Component != "" {
		return "component:" + inc.Component
	}
	return "unknown"
}

func diffVariables(baseline, current *pipeline.Document) []Change {
	var changes []Change
	for k := range current.Variables {
		if _, ok := baseline.Variables[k]; !ok {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryVariable, Name: k})
		}
	}
	for k := range baseline.Variables {
		if _, ok := current.Variables[k]; !ok {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryVariable, Name: k})
		}
	}
	return changes
}

func diffStages(baseline, current *pipeline.Document) []Change {
	var changes []Change
	baseSet := map[string]bool{}
	for _, s := range baseline.Stages {
		baseSet[s] = true
	}
	curSet := map[string]bool{}
	for _, s := range current.Stages {
		curSet[s] = true
	}
	for _, s := range current.Stages {
		if !baseSet[s] {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryStage, Name: s})
		}
	}
	for _, s := range baseline.Stages {
		if !curSet[s] {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryStage, Name: s})
		}
	}
	return changes
}
```

- [ ] **Step 4: Write failing test for security impact assessment**

Create `pkg/drift/security_test.go`:

```go
package drift

import "testing"

func TestAssessSecurityImpact(t *testing.T) {
	tests := []struct {
		name       string
		changes    []Change
		wantSev    string
		wantMinLen int
	}{
		{
			name: "security_job_removed",
			changes: []Change{
				{Type: ChangeRemoved, Category: CategoryJob, Name: "sast-scan"},
			},
			wantSev:    "CRITICAL",
			wantMinLen: 1,
		},
		{
			name: "remote_include_added",
			changes: []Change{
				{Type: ChangeAdded, Category: CategoryInclude, Name: "remote:https://evil.com/ci.yml"},
			},
			wantSev:    "HIGH",
			wantMinLen: 1,
		},
		{
			name: "script_changed",
			changes: []Change{
				{Type: ChangeModified, Category: CategoryScript, Name: "deploy"},
			},
			wantSev:    "MEDIUM",
			wantMinLen: 1,
		},
		{
			name: "variable_added",
			changes: []Change{
				{Type: ChangeAdded, Category: CategoryVariable, Name: "NEW_VAR"},
			},
			wantSev:    "LOW",
			wantMinLen: 1,
		},
		{
			name:       "no_changes",
			changes:    nil,
			wantMinLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssessSecurityImpact(tt.changes)
			if len(got) < tt.wantMinLen {
				t.Errorf("expected at least %d security changes, got %d", tt.wantMinLen, len(got))
			}
			if tt.wantSev != "" && len(got) > 0 {
				if string(got[0].Severity) != tt.wantSev {
					t.Errorf("expected severity %s, got %s", tt.wantSev, got[0].Severity)
				}
			}
		})
	}
}
```

- [ ] **Step 5: Implement security impact assessment**

Create `pkg/drift/security.go`:

```go
package drift

import (
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

type SecurityChange struct {
	Severity    analyze.Severity `json:"severity"`
	Category    string           `json:"category"`
	Description string           `json:"description"`
	Change      Change           `json:"change"`
}

var securityJobPatterns = []string{
	"sast", "dast", "secret", "dependency", "container_scan",
	"license_scan", "security", "vulnerability", "gemnasium",
	"trivy", "semgrep", "bandit", "gosec", "brakeman",
}

func AssessSecurityImpact(changes []Change) []SecurityChange {
	var impacts []SecurityChange
	for _, c := range changes {
		switch {
		case c.Type == ChangeRemoved && c.Category == CategoryJob && isSecurityJob(c.Name):
			impacts = append(impacts, SecurityChange{
				Severity:    analyze.SeverityCritical,
				Category:    "security_job_removed",
				Description: fmt.Sprintf("Security scanning job '%s' was removed", c.Name),
				Change:      c,
			})
		case c.Type == ChangeAdded && c.Category == CategoryInclude && strings.HasPrefix(c.Name, "remote:"):
			impacts = append(impacts, SecurityChange{
				Severity:    analyze.SeverityHigh,
				Category:    "remote_include_added",
				Description: fmt.Sprintf("New remote include added: %s", c.Name),
				Change:      c,
			})
		case c.Type == ChangeRemoved && c.Category == CategoryInclude:
			impacts = append(impacts, SecurityChange{
				Severity:    analyze.SeverityMedium,
				Category:    "include_removed",
				Description: fmt.Sprintf("CI include removed: %s", c.Name),
				Change:      c,
			})
		case c.Type == ChangeModified && c.Category == CategoryScript:
			impacts = append(impacts, SecurityChange{
				Severity:    analyze.SeverityMedium,
				Category:    "script_changed",
				Description: fmt.Sprintf("Script content changed in job '%s'", c.Name),
				Change:      c,
			})
		case c.Type == ChangeAdded && c.Category == CategoryVariable:
			impacts = append(impacts, SecurityChange{
				Severity:    analyze.SeverityLow,
				Category:    "variable_added",
				Description: fmt.Sprintf("New variable added: %s", c.Name),
				Change:      c,
			})
		case c.Type == ChangeRemoved && c.Category == CategoryVariable:
			impacts = append(impacts, SecurityChange{
				Severity:    analyze.SeverityLow,
				Category:    "variable_removed",
				Description: fmt.Sprintf("Variable removed: %s", c.Name),
				Change:      c,
			})
		}
	}
	return impacts
}

func isSecurityJob(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range securityJobPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 6: Implement baseline storage**

Create `pkg/drift/baseline.go`:

```go
package drift

import (
	"crypto/sha256"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type ConfigBaseline struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	ProjectID   int64     `json:"project_id"`
	ProjectPath string    `json:"project_path"`
	Ref         string    `json:"ref"`
	ConfigHash  string    `json:"config_hash"`
	ConfigYAML  string    `gorm:"type:text" json:"config_yaml"`
	SavedAt     time.Time `json:"saved_at"`
}

func SaveBaseline(db *gorm.DB, projectID int64, projectPath, ref, yaml string) error {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(yaml)))
	baseline := ConfigBaseline{
		ProjectID:   projectID,
		ProjectPath: projectPath,
		Ref:         ref,
		ConfigHash:  hash,
		ConfigYAML:  yaml,
		SavedAt:     time.Now(),
	}
	return db.Where("project_id = ?", projectID).
		Assign(baseline).
		FirstOrCreate(&baseline).Error
}

func LoadBaseline(db *gorm.DB, projectID int64) (*ConfigBaseline, error) {
	var b ConfigBaseline
	err := db.Where("project_id = ?", projectID).First(&b).Error
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func HasChanged(db *gorm.DB, projectID int64, currentYAML string) (bool, error) {
	b, err := LoadBaseline(db, projectID)
	if err != nil {
		return true, err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(currentYAML)))
	return hash != b.ConfigHash, nil
}
```

Create `pkg/drift/baseline_test.go`:

```go
package drift

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&ConfigBaseline{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestSaveAndLoadBaseline(t *testing.T) {
	db := openTestDB(t)
	yaml := "stages:\n  - build\nbuild:\n  script: make"

	if err := SaveBaseline(db, 42, "group/project", "main", yaml); err != nil {
		t.Fatalf("save: %v", err)
	}

	b, err := LoadBaseline(db, 42)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.ProjectID != 42 {
		t.Errorf("project_id = %d, want 42", b.ProjectID)
	}
	if b.ConfigYAML != yaml {
		t.Errorf("yaml mismatch")
	}
}

func TestHasChanged(t *testing.T) {
	db := openTestDB(t)
	yaml := "build:\n  script: make"
	SaveBaseline(db, 1, "p", "main", yaml)

	changed, err := HasChanged(db, 1, yaml)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected no change for same yaml")
	}

	changed, err = HasChanged(db, 1, yaml+" modified")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected change for modified yaml")
	}
}
```

- [ ] **Step 7: Implement the drift CLI command**

Create `cmd/drift.go`:

```go
package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/drift"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	driftProject         string
	driftRef             string
	driftBaselineRef     string
	driftSaveBaseline    bool
	driftCompareBaseline bool
	driftFormat          string
	driftOutput          string
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Detect CI/CD configuration changes between two points in time",
	Long:  "Compare a project's .gitlab-ci.yml between refs or against a stored baseline to detect security-relevant changes.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if driftProject == "" {
			return fmt.Errorf("--project is required")
		}
		ctx := context.Background()
		client, err := newGitLabClient()
		if err != nil {
			return err
		}

		proj, _, err := client.GL.Projects.GetProject(driftProject, nil, gitlab.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("get project: %w", err)
		}

		currentRef := driftRef
		if currentRef == "" {
			currentRef = proj.DefaultBranch
		}

		currentYAML, err := fetchCIYAML(ctx, client, proj.ID, currentRef)
		if err != nil {
			return fmt.Errorf("fetch current CI config: %w", err)
		}
		currentDoc, err := pipeline.Parse(strings.NewReader(currentYAML))
		if err != nil {
			return fmt.Errorf("parse current config: %w", err)
		}

		var baselineDoc *pipeline.Document
		var baselineRefName string

		if driftSaveBaseline {
			db, derr := store.Open("")
			if derr != nil {
				return fmt.Errorf("open db: %w", derr)
			}
			if err := db.AutoMigrate(&drift.ConfigBaseline{}); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			if err := drift.SaveBaseline(db, proj.ID, proj.PathWithNamespace, currentRef, currentYAML); err != nil {
				return fmt.Errorf("save baseline: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Baseline saved for %s at ref %s\n", proj.PathWithNamespace, currentRef)
			return nil
		}

		if driftCompareBaseline {
			db, derr := store.Open("")
			if derr != nil {
				return fmt.Errorf("open db: %w", derr)
			}
			if err := db.AutoMigrate(&drift.ConfigBaseline{}); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			b, err := drift.LoadBaseline(db, proj.ID)
			if err != nil {
				return fmt.Errorf("load baseline: %w", err)
			}
			baselineDoc, err = pipeline.Parse(strings.NewReader(b.ConfigYAML))
			if err != nil {
				return fmt.Errorf("parse baseline: %w", err)
			}
			baselineRefName = fmt.Sprintf("baseline@%s", b.Ref)
		} else if driftBaselineRef != "" {
			baselineYAML, err := fetchCIYAML(ctx, client, proj.ID, driftBaselineRef)
			if err != nil {
				return fmt.Errorf("fetch baseline CI config: %w", err)
			}
			baselineDoc, err = pipeline.Parse(strings.NewReader(baselineYAML))
			if err != nil {
				return fmt.Errorf("parse baseline config: %w", err)
			}
			baselineRefName = driftBaselineRef
		} else {
			return fmt.Errorf("provide --baseline-ref or --compare-baseline")
		}

		report := drift.Diff(baselineDoc, currentDoc)
		report.ProjectPath = proj.PathWithNamespace
		report.CurrentRef = currentRef
		report.BaselineRef = baselineRefName
		report.SecurityImpact = drift.AssessSecurityImpact(report.Changes)

		w := cmd.OutOrStdout()
		if driftOutput != "" {
			f, err := os.Create(driftOutput)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}

		switch strings.ToLower(driftFormat) {
		case "json":
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		default:
			renderDriftText(w, report)
			return nil
		}
	},
}

func fetchCIYAML(ctx context.Context, cl *gitlabx.Client, projectID int64, ref string) (string, error) {
	file, resp, err := cl.GL.RepositoryFiles.GetFile(projectID, ".gitlab-ci.yml",
		&gitlab.GetFileOptions{Ref: &ref}, gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			return "", fmt.Errorf("no .gitlab-ci.yml at ref %s", ref)
		}
		return "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return string(decoded), nil
}

func renderDriftText(w interface{ Write([]byte) (int, error) }, report drift.DriftReport) {
	header := pterm.DefaultHeader.WithFullWidth()
	fmt.Fprintln(w, header.Sprint(fmt.Sprintf("CI/CD Config Drift: %s", report.ProjectPath)))
	fmt.Fprintf(w, "Baseline: %s → Current: %s\n\n", report.BaselineRef, report.CurrentRef)

	if len(report.Changes) == 0 {
		fmt.Fprintln(w, pterm.Green("No changes detected."))
		return
	}

	fmt.Fprintf(w, "Changes: %d total\n\n", len(report.Changes))
	for _, c := range report.Changes {
		prefix := "  "
		switch c.Type {
		case drift.ChangeAdded:
			prefix = pterm.Green("+ ")
		case drift.ChangeRemoved:
			prefix = pterm.Red("- ")
		case drift.ChangeModified:
			prefix = pterm.Yellow("~ ")
		}
		fmt.Fprintf(w, "%s[%s] %s", prefix, c.Category, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(w, " (%s)", c.Detail)
		}
		fmt.Fprintln(w)
	}

	if len(report.SecurityImpact) > 0 {
		fmt.Fprintln(w, "\nSecurity Impact:")
		for _, si := range report.SecurityImpact {
			fmt.Fprintf(w, "  [%s] %s\n", si.Severity, si.Description)
		}
	}
}

func init() {
	rootCmd.AddCommand(driftCmd)
	driftCmd.Flags().StringVar(&driftProject, "project", "", "Project ID or path-with-namespace (required)")
	driftCmd.Flags().StringVar(&driftRef, "ref", "", "Current ref to compare (default: default branch)")
	driftCmd.Flags().StringVar(&driftBaselineRef, "baseline-ref", "", "Git ref to use as baseline")
	driftCmd.Flags().BoolVar(&driftSaveBaseline, "save-baseline", false, "Save current config as baseline")
	driftCmd.Flags().BoolVar(&driftCompareBaseline, "compare-baseline", false, "Compare against stored baseline")
	driftCmd.Flags().StringVarP(&driftFormat, "format", "f", "text", "Output format: text|json")
	driftCmd.Flags().StringVarP(&driftOutput, "output", "o", "", "Write output to file")
}
```


- [ ] **Step 8: Add ConfigBaseline to store migrations**

In `pkg/store/models.go`, add `drift.ConfigBaseline` to the `AutoMigrate` call if it exists, or import and auto-migrate in the drift command itself (as shown in Step 7).

- [ ] **Step 9: Build and test**

Run: `cd /home/phil/projects/gogatoz && go build ./... && go test -race ./pkg/drift/ -v`
Expected: All tests pass

- [ ] **Step 10: Commit**

```bash
git add pkg/drift/ cmd/drift.go
git commit -m "feat: add CI/CD config drift detection (feature 24)"
```

---

### Task 6: Group-Level Security Dashboard (Feature 23)

New `gogatoz dashboard` subcommand with group-wide security scorecard, PTerm CLI output, and HTML dashboard.

**Files:**
- Create: `pkg/dashboard/dashboard.go`
- Create: `pkg/dashboard/dashboard_test.go`
- Create: `pkg/dashboard/scorer.go`
- Create: `pkg/dashboard/scorer_test.go`
- Create: `pkg/dashboard/pterm.go`
- Create: `pkg/dashboard/html.go`
- Create: `pkg/dashboard/html_template.html`
- Create: `cmd/dashboard.go`

**Interfaces:**
- Consumes: `[]enumerate.Result` (from live scan, JSONL file, or SQLite DB)
- Produces: `Dashboard` struct, `Build(results []enumerate.Result, groupName string, groupID int64) Dashboard`
- Produces: `ScoreProject(result enumerate.Result) ProjectScorecard`
- Produces: `RenderPTerm(w io.Writer, d Dashboard)`, `RenderHTML(w io.Writer, d Dashboard, version string) error`

- [ ] **Step 1: Write failing test for scorer**

Create `pkg/dashboard/scorer_test.go`:

```go
package dashboard

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestScoreProject(t *testing.T) {
	tests := []struct {
		name     string
		result   enumerate.Result
		wantTier string
		wantMin  int
		wantMax  int
	}{
		{
			name: "clean_project",
			result: enumerate.Result{
				ProjectPathWithNS: "group/clean",
				HasCIPipeline:     true,
				ProtectedBranches: []string{"main"},
			},
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
		{
			name: "critical_findings",
			result: enumerate.Result{
				ProjectPathWithNS: "group/vuln",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "TEST", Severity: analyze.SeverityCritical},
					{ID: "TEST2", Severity: analyze.SeverityCritical},
				},
			},
			wantTier: "Critical",
			wantMin:  0,
			wantMax:  20,
		},
		{
			name: "medium_findings",
			result: enumerate.Result{
				ProjectPathWithNS: "group/med",
				HasCIPipeline:     true,
				Findings: []analyze.Finding{
					{ID: "T1", Severity: analyze.SeverityMedium},
					{ID: "T2", Severity: analyze.SeverityMedium},
					{ID: "T3", Severity: analyze.SeverityMedium},
				},
			},
			wantTier: "Low",
			wantMin:  61,
			wantMax:  100,
		},
		{
			name: "no_ci",
			result: enumerate.Result{
				ProjectPathWithNS: "group/noci",
				HasCIPipeline:     false,
			},
			wantTier: "Clean",
			wantMin:  81,
			wantMax:  100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := ScoreProject(tt.result)
			if sc.Score < tt.wantMin || sc.Score > tt.wantMax {
				t.Errorf("score = %d, want [%d, %d]", sc.Score, tt.wantMin, tt.wantMax)
			}
			if sc.RiskTier != tt.wantTier {
				t.Errorf("tier = %s, want %s", sc.RiskTier, tt.wantTier)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/phil/projects/gogatoz && go test -run TestScoreProject ./pkg/dashboard/ -v`
Expected: FAIL — package not found

- [ ] **Step 3: Implement scorer**

Create `pkg/dashboard/scorer.go`:

```go
package dashboard

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

type ProjectScorecard struct {
	ProjectPath         string         `json:"project_path"`
	Score               int            `json:"score"`
	RiskTier            string         `json:"risk_tier"`
	FindingsBySeverity  map[string]int `json:"findings_by_severity"`
	HasCI               bool           `json:"has_ci"`
	HasSecurityJobs     bool           `json:"has_security_jobs"`
	HasProtectedBranches bool          `json:"has_protected_branches"`
}

var securityJobNames = []string{
	"sast", "dast", "secret", "dependency", "container_scan",
	"license_scan", "security", "semgrep", "trivy", "bandit",
}

func ScoreProject(r enumerate.Result) ProjectScorecard {
	sc := ProjectScorecard{
		ProjectPath:         r.ProjectPathWithNS,
		HasCI:               r.HasCIPipeline,
		HasProtectedBranches: len(r.ProtectedBranches) > 0,
		FindingsBySeverity:  map[string]int{},
	}

	score := 100
	for _, f := range r.Findings {
		if f.FalsePositive {
			continue
		}
		sc.FindingsBySeverity[string(f.Severity)]++
		switch f.Severity {
		case analyze.SeverityCritical:
			score -= 15
		case analyze.SeverityHigh:
			score -= 8
		case analyze.SeverityMedium:
			score -= 3
		case analyze.SeverityLow:
			score -= 1
		}
	}

	for _, f := range r.Findings {
		lower := strings.ToLower(f.JobName)
		for _, pat := range securityJobNames {
			if strings.Contains(lower, pat) {
				sc.HasSecurityJobs = true
				break
			}
		}
		if sc.HasSecurityJobs {
			break
		}
	}

	if sc.HasSecurityJobs {
		score += 5
	}
	if sc.HasProtectedBranches {
		score += 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	sc.Score = score

	switch {
	case score <= 20:
		sc.RiskTier = "Critical"
	case score <= 40:
		sc.RiskTier = "High"
	case score <= 60:
		sc.RiskTier = "Medium"
	case score <= 80:
		sc.RiskTier = "Low"
	default:
		sc.RiskTier = "Clean"
	}

	return sc
}
```

- [ ] **Step 4: Write failing test for dashboard Build**

Create `pkg/dashboard/dashboard_test.go`:

```go
package dashboard

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

func TestBuild(t *testing.T) {
	results := []enumerate.Result{
		{
			ProjectPathWithNS: "group/clean",
			HasCIPipeline:     true,
			ProtectedBranches: []string{"main"},
		},
		{
			ProjectPathWithNS: "group/vuln",
			HasCIPipeline:     true,
			Findings: []analyze.Finding{
				{ID: "TEST", Severity: analyze.SeverityCritical},
				{ID: "TEST2", Severity: analyze.SeverityHigh},
			},
		},
		{
			ProjectPathWithNS: "group/noci",
			HasCIPipeline:     false,
		},
	}

	d := Build(results, "test-group", 1)

	if d.GroupName != "test-group" {
		t.Errorf("GroupName = %s, want test-group", d.GroupName)
	}
	if d.ProjectCount != 3 {
		t.Errorf("ProjectCount = %d, want 3", d.ProjectCount)
	}
	if d.ScannedCount != 3 {
		t.Errorf("ScannedCount = %d, want 3", d.ScannedCount)
	}
	if len(d.Scorecards) != 3 {
		t.Errorf("Scorecards len = %d, want 3", len(d.Scorecards))
	}
	if d.Aggregate.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", d.Aggregate.TotalFindings)
	}
	if d.Aggregate.TotalCritical != 1 {
		t.Errorf("TotalCritical = %d, want 1", d.Aggregate.TotalCritical)
	}
	if len(d.TopFindings) == 0 {
		t.Error("expected at least 1 top finding")
	}
}

func TestBuild_Empty(t *testing.T) {
	d := Build(nil, "empty", 0)
	if d.ProjectCount != 0 {
		t.Errorf("expected 0 projects, got %d", d.ProjectCount)
	}
}
```

- [ ] **Step 5: Implement dashboard Build**

Create `pkg/dashboard/dashboard.go`:

```go
package dashboard

import (
	"sort"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
)

type Dashboard struct {
	GroupName        string             `json:"group_name"`
	GroupID          int64              `json:"group_id"`
	GeneratedAt      time.Time          `json:"generated_at"`
	ProjectCount     int                `json:"project_count"`
	ScannedCount     int                `json:"scanned_count"`
	Scorecards       []ProjectScorecard `json:"scorecards"`
	Aggregate        AggregateMetrics   `json:"aggregate"`
	TopFindings      []FindingFrequency `json:"top_findings"`
	RiskDistribution RiskDistribution   `json:"risk_distribution"`
}

type AggregateMetrics struct {
	MeanScore              int     `json:"mean_score"`
	MedianScore            int     `json:"median_score"`
	CICoverage             float64 `json:"ci_coverage"`
	SecurityJobCoverage    float64 `json:"security_job_coverage"`
	ProtectedBranchCoverage float64 `json:"protected_branch_coverage"`
	TotalFindings          int     `json:"total_findings"`
	TotalCritical          int     `json:"total_critical"`
	TotalHigh              int     `json:"total_high"`
}

type FindingFrequency struct {
	FindingID    string `json:"finding_id"`
	Count        int    `json:"count"`
	ProjectCount int    `json:"project_count"`
	Severity     string `json:"severity"`
}

type RiskDistribution struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Clean    int `json:"clean"`
}

func Build(results []enumerate.Result, groupName string, groupID int64) Dashboard {
	d := Dashboard{
		GroupName:    groupName,
		GroupID:      groupID,
		GeneratedAt:  time.Now(),
		ProjectCount: len(results),
		ScannedCount: len(results),
	}

	if len(results) == 0 {
		return d
	}

	scores := make([]int, 0, len(results))
	findingCounts := map[string]int{}
	findingProjects := map[string]map[string]bool{}
	findingSeverity := map[string]string{}
	ciCount, secJobCount, protCount := 0, 0, 0

	for _, r := range results {
		sc := ScoreProject(r)
		d.Scorecards = append(d.Scorecards, sc)
		scores = append(scores, sc.Score)

		switch sc.RiskTier {
		case "Critical":
			d.RiskDistribution.Critical++
		case "High":
			d.RiskDistribution.High++
		case "Medium":
			d.RiskDistribution.Medium++
		case "Low":
			d.RiskDistribution.Low++
		case "Clean":
			d.RiskDistribution.Clean++
		}

		if sc.HasCI {
			ciCount++
		}
		if sc.HasSecurityJobs {
			secJobCount++
		}
		if sc.HasProtectedBranches {
			protCount++
		}

		for _, f := range r.Findings {
			if f.FalsePositive {
				continue
			}
			d.Aggregate.TotalFindings++
			switch f.Severity {
			case analyze.SeverityCritical:
				d.Aggregate.TotalCritical++
			case analyze.SeverityHigh:
				d.Aggregate.TotalHigh++
			}

			findingCounts[f.ID]++
			if findingProjects[f.ID] == nil {
				findingProjects[f.ID] = map[string]bool{}
			}
			findingProjects[f.ID][r.ProjectPathWithNS] = true
			findingSeverity[f.ID] = string(f.Severity)
		}
	}

	sort.Ints(scores)
	total := 0
	for _, s := range scores {
		total += s
	}
	d.Aggregate.MeanScore = total / len(scores)
	d.Aggregate.MedianScore = scores[len(scores)/2]

	n := float64(len(results))
	d.Aggregate.CICoverage = float64(ciCount) / n * 100
	d.Aggregate.SecurityJobCoverage = float64(secJobCount) / n * 100
	d.Aggregate.ProtectedBranchCoverage = float64(protCount) / n * 100

	for id, count := range findingCounts {
		d.TopFindings = append(d.TopFindings, FindingFrequency{
			FindingID:    id,
			Count:        count,
			ProjectCount: len(findingProjects[id]),
			Severity:     findingSeverity[id],
		})
	}
	sort.Slice(d.TopFindings, func(i, j int) bool {
		return d.TopFindings[i].Count > d.TopFindings[j].Count
	})
	if len(d.TopFindings) > 20 {
		d.TopFindings = d.TopFindings[:20]
	}

	sort.Slice(d.Scorecards, func(i, j int) bool {
		return d.Scorecards[i].Score < d.Scorecards[j].Score
	})

	return d
}
```

- [ ] **Step 6: Implement PTerm renderer**

Create `pkg/dashboard/pterm.go`:

```go
package dashboard

import (
	"fmt"
	"io"

	"github.com/pterm/pterm"
)

func RenderPTerm(w io.Writer, d Dashboard) {
	header := pterm.DefaultHeader.WithFullWidth()
	fmt.Fprintln(w, header.Sprint(fmt.Sprintf("Security Dashboard: %s", d.GroupName)))

	fmt.Fprintf(w, "Projects: %d | Mean Score: %d | Median Score: %d\n",
		d.ProjectCount, d.Aggregate.MeanScore, d.Aggregate.MedianScore)
	fmt.Fprintf(w, "CI Coverage: %.0f%% | Security Jobs: %.0f%% | Protected Branches: %.0f%%\n\n",
		d.Aggregate.CICoverage, d.Aggregate.SecurityJobCoverage, d.Aggregate.ProtectedBranchCoverage)

	fmt.Fprintf(w, "Risk Distribution: Critical=%d High=%d Medium=%d Low=%d Clean=%d\n\n",
		d.RiskDistribution.Critical, d.RiskDistribution.High,
		d.RiskDistribution.Medium, d.RiskDistribution.Low, d.RiskDistribution.Clean)

	tableData := pterm.TableData{{"Project", "Score", "Tier", "CRIT", "HIGH", "MED", "LOW", "CI", "SecJobs", "Protected"}}
	for _, sc := range d.Scorecards {
		ci, sec, prot := "no", "no", "no"
		if sc.HasCI {
			ci = "yes"
		}
		if sc.HasSecurityJobs {
			sec = "yes"
		}
		if sc.HasProtectedBranches {
			prot = "yes"
		}
		tableData = append(tableData, []string{
			sc.ProjectPath,
			fmt.Sprintf("%d", sc.Score),
			sc.RiskTier,
			fmt.Sprintf("%d", sc.FindingsBySeverity["CRITICAL"]),
			fmt.Sprintf("%d", sc.FindingsBySeverity["HIGH"]),
			fmt.Sprintf("%d", sc.FindingsBySeverity["MEDIUM"]),
			fmt.Sprintf("%d", sc.FindingsBySeverity["LOW"]),
			ci, sec, prot,
		})
	}
	s, _ := pterm.DefaultTable.WithHasHeader().WithData(tableData).Srender()
	fmt.Fprintln(w, s)

	if len(d.TopFindings) > 0 {
		fmt.Fprintln(w, "\nTop Findings:")
		for _, f := range d.TopFindings {
			fmt.Fprintf(w, "  [%s] %s — %d occurrences across %d projects\n",
				f.Severity, f.FindingID, f.Count, f.ProjectCount)
		}
	}
}
```

- [ ] **Step 7: Implement HTML dashboard**

Create `pkg/dashboard/html.go` and `pkg/dashboard/html_template.html` following the same embedded template pattern as `pkg/enumerate/report/html.go`. The HTML template should be a self-contained Bootstrap 5 + Chart.js page with:

- Group header with overall score gauge
- Risk distribution doughnut chart
- Project scorecard DataTable (sortable, searchable)
- Top findings horizontal bar chart
- Coverage metrics cards

The implementation follows the exact pattern from `pkg/enumerate/report/html.go`:

```go
package dashboard

import (
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"time"
)

//go:embed html_template.html
var htmlFS embed.FS

type HTMLData struct {
	Dashboard
	Version          string
	RiskDistJSON     template.JS
	TopFindingsJSON  template.JS
}

func RenderHTML(w io.Writer, d Dashboard, version string) error {
	riskDist, _ := json.Marshal(d.RiskDistribution)
	topFindings, _ := json.Marshal(d.TopFindings)

	data := HTMLData{
		Dashboard:       d,
		Version:         version,
		RiskDistJSON:    template.JS(riskDist),
		TopFindingsJSON: template.JS(topFindings),
	}

	tmplContent, err := htmlFS.ReadFile("html_template.html")
	if err != nil {
		return err
	}
	tmpl, err := template.New("dashboard").Parse(string(tmplContent))
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}
```

The `html_template.html` file should be a self-contained HTML page with embedded Chart.js and Bootstrap CSS (similar to the 572-line template in `pkg/enumerate/report/html_template.html`).

- [ ] **Step 8: Implement dashboard CLI command**

Create `cmd/dashboard.go`:

```go
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/dashboard"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	enumorg "github.com/mr-pmillz/gogatoz/pkg/enumerate/org"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

var (
	dashGroup  string
	dashFromDB bool
	dashJSONL  string
	dashScan   bool
	dashFormat string
	dashOutput string
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Generate a group-level security dashboard",
	Long:  "Aggregate security posture across all projects in a GitLab group into a scorecard dashboard.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if dashGroup == "" && dashJSONL == "" {
			return fmt.Errorf("--group or --from-jsonl is required")
		}

		var results []enumerate.Result
		var groupName string
		var groupID int64

		if dashJSONL != "" {
			f, err := os.Open(dashJSONL)
			if err != nil {
				return fmt.Errorf("open jsonl: %w", err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
			for scanner.Scan() {
				var r enumerate.Result
				if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
					continue
				}
				results = append(results, r)
			}
			groupName = dashJSONL
		} else {
			ctx := context.Background()
			client, err := newGitLabClient()
			if err != nil {
				return err
			}

			projs, err := enumorg.ListGroupProjects(ctx, client, dashGroup, true)
			if err != nil {
				return fmt.Errorf("list group projects: %w", err)
			}

			opts := enumerate.Options{
				Concurrency:    runtime.GOMAXPROCS(0),
				FollowIncludes: true,
				IncludeDepth:   2,
				FetchProtected: true,
			}
			results, err = enumerate.EnumerateProjects(ctx, client, projs, opts)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", err)
			}
			groupName = dashGroup
		}

		d := dashboard.Build(results, groupName, groupID)

		w := cmd.OutOrStdout()
		if dashOutput != "" {
			f, err := os.Create(dashOutput)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}

		switch strings.ToLower(dashFormat) {
		case "json":
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(d)
		case "html":
			return dashboard.RenderHTML(w, d, version)
		default:
			dashboard.RenderPTerm(w, d)
			return nil
		}
	},
}

func init() {
	rootCmd.AddCommand(dashboardCmd)
	dashboardCmd.Flags().StringVar(&dashGroup, "group", "", "GitLab group ID or path")
	dashboardCmd.Flags().BoolVar(&dashFromDB, "from-db", false, "Load results from SQLite database")
	dashboardCmd.Flags().StringVar(&dashJSONL, "from-jsonl", "", "Load results from JSONL file")
	dashboardCmd.Flags().BoolVar(&dashScan, "scan", false, "Run live enumerate scan (default if no other source)")
	dashboardCmd.Flags().StringVarP(&dashFormat, "format", "f", "text", "Output format: text|json|html")
	dashboardCmd.Flags().StringVarP(&dashOutput, "output", "o", "", "Write output to file")
}
```

- [ ] **Step 9: Build and test**

Run: `cd /home/phil/projects/gogatoz && go build ./... && go test -race ./pkg/dashboard/ -v`
Expected: All tests pass

- [ ] **Step 10: Commit**

```bash
git add pkg/dashboard/ cmd/dashboard.go
git commit -m "feat: add group-level security dashboard (feature 23)"
```

---

### Task 7: Integration, Report Enrichment, and Final Verification

Wire all new findings into the report pipeline, add exploitable mappings, and run full build verification.

**Files:**
- Modify: `pkg/enumerate/report/report.go` — add new report sections for variables, environments
- Modify: `pkg/enumerate/report/pterm.go` — render new sections
- Modify: `pkg/enumerate/report/exploit.go` — add exploitable mappings for new findings
- Modify: `pkg/enumerate/report/html.go` + `html_template.html` — add new HTML sections

**Interfaces:**
- Consumes: All new finding IDs from Tasks 1-4
- Produces: Updated report rendering with new sections

- [ ] **Step 1: Add exploitable mappings**

In `pkg/enumerate/report/exploit.go`, add to `exploitableFindingMap`:

```go
	"PAGES_MR_DEPLOY_RISK":   cmdPwnRequest,
	"ENV_UNPROTECTED_DEPLOY": cmdPwnRequest,
	"ENV_MR_DEPLOY_RISK":     cmdPwnRequest,
	"VAR_UNPROTECTED_SECRET": cmdSecretsExfil,
	"VAR_MR_OVERRIDE_RISK":   cmdVarInject,
```

- [ ] **Step 2: Add report pipeline counting for new finding IDs**

In `pkg/enumerate/report/report.go`, in the `Build()` function's finding ID switch, add the new IDs to appropriate categories. For example, environment and pages findings can be added to pipeline risk counting.

- [ ] **Step 3: Run full build and test suite**

```bash
cd /home/phil/projects/gogatoz
go build ./...
go test -race ./...
```

Expected: All existing and new tests pass. No compilation errors.

- [ ] **Step 4: Run linter**

```bash
cd /home/phil/projects/gogatoz
make lint
```

Expected: No new lint errors (existing exclusions still apply).

- [ ] **Step 5: Commit**

```bash
git add pkg/enumerate/report/
git commit -m "feat: integrate new findings into report pipeline and exploitable mappings"
```

- [ ] **Step 6: QA against CTF lab**

Invoke the `ctf-qa-validation` skill to test each feature against the live CTF environment at `gitlab.local:8929`. Test:

1. Pages: enumerate a project with a pages job and verify PAGES_* findings appear
2. SBOM: run `gogatoz pbom --format spdx` and verify valid SPDX JSON output
3. Variables: enumerate with `--fetch-variables` and verify VAR_* findings
4. Environments: enumerate with `--fetch-environments` and verify ENV_* findings
5. Drift: run `gogatoz drift --project <id> --save-baseline` then modify config and `--compare-baseline`
6. Dashboard: run `gogatoz dashboard --group <group> --format html -o dashboard.html`

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "test: QA validation of all 6 new features against CTF lab"
```
