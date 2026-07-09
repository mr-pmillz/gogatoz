package pbom

import "time"

// Version is the PBOM schema version.
const Version = "1.0.0"

// PBOM represents a Pipeline Bill of Materials — an inventory of all container
// images and CI include references used in a GitLab CI/CD pipeline.
type PBOM struct {
	PBOMVersion     string           `json:"pbomVersion"`
	GeneratedAt     time.Time        `json:"generatedAt"`
	Project         ProjectInfo      `json:"project"`
	Summary         Summary          `json:"summary"`
	ContainerImages []ContainerImage `json:"containerImages"`
	Includes        []PBOMInclude    `json:"includes"`
}

// ProjectInfo identifies the GitLab project the PBOM was generated for.
type ProjectInfo struct {
	Path   string `json:"path,omitempty"`
	ID     int64  `json:"id,omitempty"`
	URL    string `json:"url,omitempty"`
	Branch string `json:"branch,omitempty"`
}

// Summary provides aggregate counts for the PBOM.
type Summary struct {
	TotalImages   int `json:"totalImages"`
	TotalIncludes int `json:"totalIncludes"`
	UniqueImages  int `json:"uniqueImages"`
}

// ContainerImage represents a single container image reference found in the
// pipeline, along with the jobs that use it.
type ContainerImage struct {
	Image    string   `json:"image"`
	Registry string   `json:"registry,omitempty"`
	Name     string   `json:"name"`
	Tag      string   `json:"tag,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Jobs     []string `json:"jobs"`
}

// PBOMInclude represents a single CI include directive found in the pipeline.
type PBOMInclude struct {
	Type      string `json:"type"`
	Location  string `json:"location"`
	Project   string `json:"project,omitempty"`
	Ref       string `json:"ref,omitempty"`
	Component string `json:"component,omitempty"`
}
