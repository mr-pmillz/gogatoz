package analyze

import (
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const IncludeRemoteCachedID = "INCLUDE_REMOTE_CACHED"

func detectIncludeRemoteCached(doc *pipeline.Document) []Finding {
	var findings []Finding

	rawIncludes, ok := doc.Raw["include"]
	if !ok {
		return nil
	}

	includes := normalizeIncludes(rawIncludes)
	for _, inc := range includes {
		m, ok := inc.(map[string]any)
		if !ok {
			continue
		}
		remote, hasRemote := m["remote"]
		if !hasRemote {
			continue
		}
		if _, hasCacheKey := m["cache"]; !hasCacheKey {
			continue
		}

		remoteURL := ""
		if s, ok := remote.(string); ok {
			remoteURL = s
		}

		findings = append(findings, Finding{
			ID:       IncludeRemoteCachedID,
			Severity: SeverityHigh,
			Title:    "Remote include with cache enabled",
			Description: "Pipeline includes a remote URL with caching enabled. " +
				"If the remote content is compromised, all pipelines using the cached include " +
				"will execute poisoned configuration for the cache TTL duration.",
			Evidence: stringutil.TruncateEvidence("remote: "+remoteURL, 200),
		})
	}

	return findings
}

func normalizeIncludes(raw any) []any {
	switch v := raw.(type) {
	case []any:
		return v
	case map[string]any:
		return []any{v}
	default:
		return nil
	}
}
