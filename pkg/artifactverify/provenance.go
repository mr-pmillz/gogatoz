package artifactverify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const (
	ProvenanceMismatchID = analyze.ProvenanceMismatchID
	ReleaseTagMismatchID = analyze.ReleaseTagMismatchID
)

// ProvenanceSummary records the source identity extracted from an attestation.
type ProvenanceSummary struct {
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Pipeline   string `json:"pipeline,omitempty"`
}

type provenanceExpectations struct {
	repository string
	commit     string
	ref        string
	pipeline   string
}

type provenanceValues struct {
	repositories []string
	commits      []string
	refs         []string
	pipelines    []string
}

var packageVersionRe = regexp.MustCompile(`(?m)^Version:\s*([^\s]+)\s*$`)

func inspectProvenance(
	ctx context.Context,
	input string,
	expected provenanceExpectations,
	maxBytes int64,
	client *http.Client,
) (*ProvenanceSummary, []analyze.Finding, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, missingProvenanceFindings(expected), nil
	}
	data, err := readInput(ctx, input, maxBytes, client)
	if err != nil {
		return nil, nil, fmt.Errorf("read provenance: %w", err)
	}
	var statement any
	if err := json.Unmarshal(data, &statement); err != nil {
		return nil, nil, fmt.Errorf("decode provenance JSON: %w", err)
	}
	values := provenanceValues{}
	collectProvenanceValues(statement, "", &values)
	values.deduplicate()
	summary := &ProvenanceSummary{
		Repository: selectValue(values.repositories, expected.repository, repositoryMatches),
		Commit:     selectValue(values.commits, expected.commit, exactValueMatches),
		Ref:        selectValue(values.refs, expected.ref, refMatches),
		Pipeline:   selectValue(values.pipelines, expected.pipeline, pipelineMatches),
	}
	return summary, expectationFindings(expected, values), nil
}

func collectProvenanceValues(value any, key string, values *provenanceValues) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			collectProvenanceValues(typed[childKey], childKey, values)
		}
	case []any:
		for _, child := range typed {
			collectProvenanceValues(child, key, values)
		}
	case string:
		classifyProvenanceValue(strings.ToLower(key), strings.TrimSpace(typed), values)
	case json.Number:
		classifyProvenanceValue(strings.ToLower(key), string(typed), values)
	case float64:
		if strings.Contains(strings.ToLower(key), "pipeline") {
			values.pipelines = append(values.pipelines, fmt.Sprintf("%.0f", typed))
		}
	}
}

func classifyProvenanceValue(key, value string, values *provenanceValues) {
	if value == "" {
		return
	}
	switch {
	case key == "repository" || key == "source" || key == "uri":
		if strings.Contains(value, "://") || strings.HasPrefix(value, "git+") {
			values.repositories = append(values.repositories, value)
		}
	case key == "gitcommit" || key == "commit" || key == "revision":
		values.commits = append(values.commits, value)
	case key == "ref" || key == "tag":
		values.refs = append(values.refs, value)
	case strings.Contains(key, "pipeline") || key == "invocationid" || key == "buildid":
		values.pipelines = append(values.pipelines, value)
	}
}

func (values *provenanceValues) deduplicate() {
	values.repositories = uniqueSorted(values.repositories)
	values.commits = uniqueSorted(values.commits)
	values.refs = uniqueSorted(values.refs)
	values.pipelines = uniqueSorted(values.pipelines)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func selectValue(values []string, expected string, match func(string, string) bool) string {
	for _, value := range values {
		if match(expected, value) {
			return value
		}
	}
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func expectationFindings(expected provenanceExpectations, values provenanceValues) []analyze.Finding {
	checks := []struct {
		field  string
		want   string
		values []string
		match  func(string, string) bool
	}{
		{field: "repository", want: expected.repository, values: values.repositories, match: repositoryMatches},
		{field: "commit", want: expected.commit, values: values.commits, match: exactValueMatches},
		{field: "ref", want: expected.ref, values: values.refs, match: refMatches},
		{field: "pipeline", want: expected.pipeline, values: values.pipelines, match: pipelineMatches},
	}
	var findings []analyze.Finding
	for _, check := range checks {
		if strings.TrimSpace(check.want) == "" || anyValueMatches(check.want, check.values, check.match) {
			continue
		}
		findings = append(findings, packageFinding(
			ProvenanceMismatchID, analyze.SeverityHigh,
			"Package provenance does not match the expected release identity",
			"The attestation is missing or disagrees with an expected repository, commit, ref, or pipeline.",
			fmt.Sprintf("field=%s expected=%s actual=%s", check.field, check.want, boundedPathList(check.values)), "",
		))
	}
	return findings
}

func missingProvenanceFindings(expected provenanceExpectations) []analyze.Finding {
	return expectationFindings(expected, provenanceValues{})
}

func anyValueMatches(expected string, values []string, match func(string, string) bool) bool {
	for _, value := range values {
		if match(expected, value) {
			return true
		}
	}
	return false
}

func exactValueMatches(expected, actual string) bool {
	return strings.EqualFold(strings.TrimSpace(expected), strings.TrimSpace(actual))
}

func repositoryMatches(expected, actual string) bool {
	return normalizeRepository(expected) == normalizeRepository(actual)
}

func normalizeRepository(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "git+")
	value = strings.TrimSuffix(value, "/")
	return strings.TrimSuffix(value, ".git")
}

func refMatches(expected, actual string) bool {
	return normalizeRef(expected) == normalizeRef(actual)
}

func normalizeRef(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "refs/tags/")
	return strings.TrimPrefix(value, "refs/heads/")
}

func pipelineMatches(expected, actual string) bool {
	expected = strings.Trim(strings.TrimSpace(expected), "/")
	actual = strings.Trim(strings.TrimSpace(actual), "/")
	return expected != "" && (actual == expected || path.Base(actual) == expected)
}

func releaseTagFindings(files []FileRecord, expectedRef string) []analyze.Finding {
	tag := strings.TrimSpace(expectedRef)
	if strings.HasPrefix(tag, "refs/heads/") || tag == "" {
		return nil
	}
	tag = strings.TrimPrefix(tag, "refs/tags/")
	version := packageVersion(files)
	if version == "" || strings.TrimPrefix(tag, "v") == strings.TrimPrefix(version, "v") {
		return nil
	}
	return []analyze.Finding{packageFinding(
		ReleaseTagMismatchID, analyze.SeverityHigh,
		"Package version does not match its release tag",
		"The version declared inside the package archive differs from the expected Git release tag.",
		fmt.Sprintf("package_version=%s expected_tag=%s", version, tag), "",
	)}
}

func packageVersion(files []FileRecord) string {
	for _, file := range files {
		base := strings.ToLower(path.Base(file.Path))
		if base == "package.json" {
			var manifest struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(file.content, &manifest) == nil && strings.TrimSpace(manifest.Version) != "" {
				return strings.TrimSpace(manifest.Version)
			}
		}
		if base == "metadata" || base == "pkg-info" {
			if match := packageVersionRe.FindSubmatch(file.content); len(match) == 2 {
				return strings.TrimSpace(string(match[1]))
			}
		}
	}
	return ""
}
