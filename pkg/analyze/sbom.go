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
