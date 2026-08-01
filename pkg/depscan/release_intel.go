package depscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const (
	DependencyCooldownID         = "DEPENDENCY_COOLDOWN"
	DormantPackageResurrectionID = "DORMANT_PACKAGE_RESURRECTION"
	DependencyReleaseBurstID     = "DEPENDENCY_RELEASE_BURST"
)

const (
	defaultRegistryTimeout    = 30 * time.Second
	defaultDormancyThreshold  = 365 * 24 * time.Hour
	defaultReleaseBurstWindow = time.Hour
	defaultReleaseBurstCount  = 3
	maxRegistryMetadataBytes  = 8 << 20
)

// Release is a registry-published package version timestamp.
type Release struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
}

// ReleaseHistory contains the non-executing registry metadata for a package.
type ReleaseHistory struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Versions  []Release `json:"versions"`
}

// ReleaseProvider retrieves package version timestamps without downloading an artifact.
type ReleaseProvider interface {
	ReleaseHistory(context.Context, string, string) (ReleaseHistory, error)
}

// ReleaseIntelOptions controls package-age and release-pattern detection.
type ReleaseIntelOptions struct {
	Cooldown          time.Duration
	DormancyThreshold time.Duration
	BurstWindow       time.Duration
	BurstThreshold    int
	Now               func() time.Time
}

// DependencyComponent is an exact dependency version extracted by depx's
// native CycloneDX exporter and optionally enriched with registry timestamps.
type DependencyComponent struct {
	Ecosystem           string        `json:"ecosystem"`
	Name                string        `json:"name"`
	Version             string        `json:"version"`
	PURL                string        `json:"purl,omitempty"`
	PublishedAt         time.Time     `json:"published_at,omitempty"`
	PreviousPublishedAt time.Time     `json:"previous_published_at,omitempty"`
	ReleaseGap          time.Duration `json:"release_gap,omitempty"`
}

// ScanReleaseIntel audits through depx once, consumes depx's native component
// export, and enriches exact versions with registry metadata. No artifact is
// downloaded and no package or lifecycle script is executed.
func (s *Scanner) ScanReleaseIntel(
	ctx context.Context,
	paths []string,
	options ReleaseIntelOptions,
) (Report, error) {
	if s == nil || s.auditor == nil {
		return Report{}, errors.New("scan dependency release intelligence: nil depx auditor")
	}
	if options.Cooldown <= 0 {
		return Report{}, errors.New("scan dependency release intelligence: cooldown must be positive")
	}
	if options.DormancyThreshold <= 0 {
		options.DormancyThreshold = defaultDormancyThreshold
	}
	if options.BurstWindow <= 0 {
		options.BurstWindow = defaultReleaseBurstWindow
	}
	if options.BurstThreshold <= 0 {
		options.BurstThreshold = defaultReleaseBurstCount
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	provider := s.releaseProvider
	if provider == nil {
		return Report{}, errors.New("scan dependency release intelligence: registry metadata provider unavailable")
	}

	report, sbom, err := s.ScanSBOM(ctx, paths, "cyclonedx")
	if err != nil {
		return Report{}, err
	}
	components, err := parseNativeComponents(sbom)
	if err != nil {
		return Report{}, fmt.Errorf("parse native depx CycloneDX components: %w", err)
	}
	slog.Info("enriching dependency release metadata", "components", len(components))
	warnings := enrichReleaseMetadata(ctx, provider, components)
	report.Components = components
	report.Warnings = append(report.Warnings, warnings...)
	report.Findings = append(report.Findings, evaluateReleaseIntel(components, options)...)
	slog.Info("dependency release metadata enriched", "components", len(components),
		"warnings", len(warnings), "findings", len(report.Findings))
	return report, nil
}

func parseNativeComponents(sbom []byte) ([]DependencyComponent, error) {
	var document struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(sbom, &document); err != nil {
		return nil, err
	}
	if document.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("unexpected SBOM format %q", document.BOMFormat)
	}
	components := make([]DependencyComponent, 0, len(document.Components))
	for _, component := range document.Components {
		name := strings.TrimSpace(component.Name)
		version := strings.TrimSpace(component.Version)
		if name == "" || version == "" {
			continue
		}
		components = append(components, DependencyComponent{
			Ecosystem: ecosystemFromPURL(component.PURL),
			Name:      name, Version: version, PURL: strings.TrimSpace(component.PURL),
		})
	}
	return components, nil
}

func enrichReleaseMetadata(ctx context.Context, provider ReleaseProvider, components []DependencyComponent) []string {
	groups := make(map[string][]int)
	for index, component := range components {
		if !supportedReleaseEcosystem(component.Ecosystem) {
			continue
		}
		key := component.Ecosystem + "\x00" + component.Name
		groups[key] = append(groups[key], index)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	const workers = 6
	semaphore := make(chan struct{}, workers)
	var waitGroup sync.WaitGroup
	var warningMu sync.Mutex
	var warnings []string
	for _, key := range keys {
		indexes := groups[key]
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			component := components[indexes[0]]
			history, err := provider.ReleaseHistory(ctx, component.Ecosystem, component.Name)
			if err != nil {
				warningMu.Lock()
				warnings = append(warnings, fmt.Sprintf("%s:%s: %v", component.Ecosystem, component.Name, err))
				warningMu.Unlock()
				return
			}
			for _, index := range indexes {
				applyReleaseHistory(&components[index], history)
			}
		}()
	}
	waitGroup.Wait()
	sort.Strings(warnings)
	return warnings
}

func applyReleaseHistory(component *DependencyComponent, history ReleaseHistory) {
	if component == nil {
		return
	}
	versions := append([]Release(nil), history.Versions...)
	sort.Slice(versions, func(i, j int) bool { return versions[i].PublishedAt.Before(versions[j].PublishedAt) })
	for index, release := range versions {
		if release.Version != component.Version || release.PublishedAt.IsZero() {
			continue
		}
		component.PublishedAt = release.PublishedAt
		if index > 0 {
			component.PreviousPublishedAt = versions[index-1].PublishedAt
			component.ReleaseGap = release.PublishedAt.Sub(versions[index-1].PublishedAt)
		}
		return
	}
}

func evaluateReleaseIntel(components []DependencyComponent, options ReleaseIntelOptions) []analyze.Finding {
	now := options.Now().UTC()
	var findings []analyze.Finding
	for _, component := range components {
		if component.PublishedAt.IsZero() {
			continue
		}
		age := now.Sub(component.PublishedAt)
		if age < 0 || age > options.Cooldown {
			continue
		}
		findings = append(findings, releaseComponentFinding(component, age, DependencyCooldownID,
			analyze.SeverityMedium, "Dependency version is inside the release cooldown"))
		if component.ReleaseGap >= options.DormancyThreshold {
			findings = append(findings, releaseComponentFinding(component, age, DormantPackageResurrectionID,
				analyze.SeverityHigh, "Dormant package published a new version"))
		}
	}
	if burst := releaseBurstFinding(components, options, now); burst != nil {
		findings = append(findings, *burst)
	}
	return findings
}

func releaseComponentFinding(
	component DependencyComponent,
	age time.Duration,
	id string,
	severity analyze.Severity,
	title string,
) analyze.Finding {
	metadata := analyze.LookupFinding(id)
	description := "Registry release metadata matched a dependency release-risk heuristic."
	recommendation := "Review the exact package release and wait for the configured cooldown before adoption."
	if metadata != nil {
		description = metadata.Description
		recommendation = metadata.Remediation
	}
	return analyze.Finding{
		ID: id, Severity: severity, Title: title, Description: description,
		Recommendation: recommendation,
		Evidence: fmt.Sprintf("ecosystem=%s package=%s version=%s published_at=%s age=%s previous_published_at=%s release_gap=%s",
			component.Ecosystem, component.Name, component.Version, component.PublishedAt.Format(time.RFC3339),
			age.Round(time.Second), formatOptionalTime(component.PreviousPublishedAt), component.ReleaseGap),
	}
}

func releaseBurstFinding(
	components []DependencyComponent,
	options ReleaseIntelOptions,
	now time.Time,
) *analyze.Finding {
	recent := make([]DependencyComponent, 0, len(components))
	for _, component := range components {
		age := now.Sub(component.PublishedAt)
		if !component.PublishedAt.IsZero() && age >= 0 && age <= options.Cooldown {
			recent = append(recent, component)
		}
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].PublishedAt.Before(recent[j].PublishedAt) })
	for start := range recent {
		end := start
		for end+1 < len(recent) && recent[end+1].PublishedAt.Sub(recent[start].PublishedAt) <= options.BurstWindow {
			end++
		}
		if end-start+1 < options.BurstThreshold {
			continue
		}
		labels := make([]string, 0, end-start+1)
		for _, component := range recent[start : end+1] {
			labels = append(labels, component.Ecosystem+":"+component.Name+"@"+component.Version)
		}
		metadata := analyze.LookupFinding(DependencyReleaseBurstID)
		finding := &analyze.Finding{
			ID: DependencyReleaseBurstID, Severity: analyze.SeverityHigh,
			Title:       "Coordinated dependency release burst",
			Description: "Several selected dependency versions were published within a narrow time window.",
			Evidence: fmt.Sprintf("release_count=%d window=%s packages=%s",
				len(labels), options.BurstWindow, strings.Join(labels, ",")),
		}
		if metadata != nil {
			finding.Description = metadata.Description
			finding.Recommendation = metadata.Remediation
		}
		return finding
	}
	return nil
}

func ecosystemFromPURL(purl string) string {
	purl = strings.ToLower(strings.TrimSpace(purl))
	switch {
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "npm"
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "pypi"
	case strings.HasPrefix(purl, "pkg:gem/"):
		return "gem"
	default:
		return ""
	}
}

func supportedReleaseEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "pypi", "gem":
		return true
	default:
		return false
	}
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.Format(time.RFC3339)
}

type registryReleaseProvider struct {
	client   *http.Client
	npmBase  *url.URL
	pypiBase *url.URL
	rubyBase *url.URL
}

func newRegistryReleaseProvider(timeout time.Duration) (*registryReleaseProvider, error) {
	if timeout <= 0 {
		timeout = defaultRegistryTimeout
	}
	npmBase, err := registryBase("GOGATOZ_NPM_REGISTRY_URL", "https://registry.npmjs.org")
	if err != nil {
		return nil, err
	}
	pypiBase, err := registryBase("GOGATOZ_PYPI_REGISTRY_URL", "https://pypi.org")
	if err != nil {
		return nil, err
	}
	rubyBase, err := registryBase("GOGATOZ_RUBYGEMS_REGISTRY_URL", "https://rubygems.org")
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: timeout}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 0 && !strings.EqualFold(request.URL.Host, via[0].URL.Host) {
			return errors.New("registry redirect changed host")
		}
		if len(via) >= 5 {
			return errors.New("too many registry redirects")
		}
		return nil
	}
	return &registryReleaseProvider{client: client, npmBase: npmBase, pypiBase: pypiBase, rubyBase: rubyBase}, nil
}

func (p *registryReleaseProvider) ReleaseHistory(ctx context.Context, ecosystem, name string) (ReleaseHistory, error) {
	name = strings.TrimSpace(name)
	if p == nil || p.client == nil {
		return ReleaseHistory{}, errors.New("nil registry release provider")
	}
	if name == "" {
		return ReleaseHistory{}, errors.New("package name is required")
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return p.npmHistory(ctx, name)
	case "pypi":
		return p.pypiHistory(ctx, name)
	case "gem":
		return p.rubyHistory(ctx, name)
	default:
		return ReleaseHistory{}, fmt.Errorf("unsupported release ecosystem %q", ecosystem)
	}
}

func (p *registryReleaseProvider) npmHistory(ctx context.Context, name string) (ReleaseHistory, error) {
	var document struct {
		Time map[string]string `json:"time"`
	}
	if err := p.fetchJSON(ctx, registryURL(p.npmBase, name), &document); err != nil {
		return ReleaseHistory{}, err
	}
	history := ReleaseHistory{Ecosystem: "npm", Name: name}
	for version, timestamp := range document.Time {
		if version == "created" || version == "modified" {
			continue
		}
		if publishedAt, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
			history.Versions = append(history.Versions, Release{Version: version, PublishedAt: publishedAt})
		}
	}
	return history, nil
}

func (p *registryReleaseProvider) pypiHistory(ctx context.Context, name string) (ReleaseHistory, error) {
	var document struct {
		Releases map[string][]struct {
			Uploaded string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := p.fetchJSON(ctx, registryURL(p.pypiBase, "pypi", name, "json"), &document); err != nil {
		return ReleaseHistory{}, err
	}
	history := ReleaseHistory{Ecosystem: "pypi", Name: name}
	for version, files := range document.Releases {
		var earliest time.Time
		for _, file := range files {
			uploaded, err := time.Parse(time.RFC3339Nano, file.Uploaded)
			if err == nil && (earliest.IsZero() || uploaded.Before(earliest)) {
				earliest = uploaded
			}
		}
		if !earliest.IsZero() {
			history.Versions = append(history.Versions, Release{Version: version, PublishedAt: earliest})
		}
	}
	return history, nil
}

func (p *registryReleaseProvider) rubyHistory(ctx context.Context, name string) (ReleaseHistory, error) {
	var versions []struct {
		Number    string `json:"number"`
		CreatedAt string `json:"created_at"`
	}
	if err := p.fetchJSON(ctx, registryURL(p.rubyBase, "api", "v1", "versions", name+".json"), &versions); err != nil {
		return ReleaseHistory{}, err
	}
	history := ReleaseHistory{Ecosystem: "gem", Name: name}
	for _, version := range versions {
		if publishedAt, err := time.Parse(time.RFC3339Nano, version.CreatedAt); err == nil {
			history.Versions = append(history.Versions, Release{Version: version.Number, PublishedAt: publishedAt})
		}
	}
	return history, nil
}

func (p *registryReleaseProvider) fetchJSON(ctx context.Context, endpoint string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "gogatoz-release-intel")
	response, err := p.client.Do(request) //nolint:gosec // endpoints are validated registry bases plus escaped package paths
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("registry metadata status %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxRegistryMetadataBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxRegistryMetadataBytes {
		return fmt.Errorf("registry metadata exceeds %d bytes", maxRegistryMetadataBytes)
	}
	return json.Unmarshal(data, destination)
}

func registryBase(environmentName, fallback string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(environmentName))
	if value == "" {
		value = fallback
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("invalid %s registry URL %q", environmentName, value)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func registryURL(base *url.URL, pathParts ...string) string {
	copyURL := *base
	segments := make([]string, 0, len(pathParts)+1)
	if basePath := strings.Trim(base.Path, "/"); basePath != "" {
		segments = append(segments, basePath)
	}
	for _, part := range pathParts {
		segments = append(segments, url.PathEscape(strings.TrimSpace(part)))
	}
	copyURL.Path = "/" + strings.Join(segments, "/")
	copyURL.RawPath = ""
	return copyURL.String()
}
