// Package refwatch detects security-relevant movement of Git branches and tags.
package refwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	RefSHAChangedID          = "REF_SHA_CHANGED"
	RefNonFastForwardID      = "REF_NON_FAST_FORWARD"
	TagTargetChangedID       = "TAG_TARGET_CHANGED"
	TagDeletedID             = "TAG_DELETED"
	TagRecreatedID           = "TAG_RECREATED"
	ShortLivedCIBranchID     = "SHORT_LIVED_CI_BRANCH"
	RefCreationBurstID       = "REF_CREATION_BURST"
	ReleaseWorkflowChangedID = "RELEASE_WORKFLOW_CHANGED"
)

const (
	defaultShortLivedWindow = 15 * time.Minute
	defaultBurstThreshold   = 5
)

var releaseCommandPattern = regexp.MustCompile(`(?i)\b(?:npm|pnpm)\s+publish\b|\byarn\s+npm\s+publish\b|\btwine\s+upload\b|\bgem\s+push\b|\bcargo\s+publish\b|\bmvn\s+deploy\b|\bgradle\s+publish\b|\bgoreleaser\b|\brelease-cli\s+create\b|\bglab\s+release\b`)

// RefState captures the immutable data needed to compare a branch or tag.
type RefState struct {
	SHA               string    `json:"sha"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	HasRecentPipeline bool      `json:"has_recent_pipeline,omitempty"`
}

// Snapshot is the observed branch and tag state at a point in time.
type Snapshot struct {
	ObservedAt time.Time           `json:"observed_at"`
	Branches   map[string]RefState `json:"branches"`
	Tags       map[string]RefState `json:"tags"`
}

// Options controls stateful ref anomaly thresholds.
type Options struct {
	ShortLivedWindow time.Duration
	BurstThreshold   int
}

// AncestryChecker reports whether oldSHA is an ancestor of newSHA for a branch.
type AncestryChecker func(ctx context.Context, branch, oldSHA, newSHA string) (bool, error)

// Monitor compares successive snapshots and retains only lifecycle metadata.
type Monitor struct {
	options       Options
	checkAncestry AncestryChecker
	previous      *Snapshot
	branchFirst   map[string]time.Time
	deletedTags   map[string]RefState
}

// NewMonitor creates an in-memory ref monitor.
func NewMonitor(options Options, checker AncestryChecker) *Monitor {
	if options.ShortLivedWindow <= 0 {
		options.ShortLivedWindow = defaultShortLivedWindow
	}
	if options.BurstThreshold <= 0 {
		options.BurstThreshold = defaultBurstThreshold
	}
	return &Monitor{
		options:       options,
		checkAncestry: checker,
		branchFirst:   make(map[string]time.Time),
		deletedTags:   make(map[string]RefState),
	}
}

// Observe compares current against the prior snapshot. The first observation
// establishes a baseline and intentionally emits no findings.
func (m *Monitor) Observe(ctx context.Context, current Snapshot) []analyze.Finding {
	if m == nil {
		return nil
	}
	if current.ObservedAt.IsZero() {
		current.ObservedAt = time.Now().UTC()
	}
	if current.Branches == nil {
		current.Branches = map[string]RefState{}
	}
	if current.Tags == nil {
		current.Tags = map[string]RefState{}
	}
	slog.Debug("observing git refs", "branches", len(current.Branches), "tags", len(current.Tags))
	if m.previous == nil {
		for name := range current.Branches {
			m.branchFirst[name] = current.ObservedAt
		}
		baseline := cloneSnapshot(current)
		m.previous = &baseline
		return nil
	}

	var findings []analyze.Finding
	findings = append(findings, m.branchFindings(ctx, current)...)
	tagFindings, createdTags := m.tagFindings(current)
	findings = append(findings, tagFindings...)
	createdBranches := countNewRefs(m.previous.Branches, current.Branches)
	if createdBranches+createdTags >= m.options.BurstThreshold {
		findings = append(findings, analyze.Finding{
			ID: RefCreationBurstID, Severity: analyze.SeverityHigh,
			Title:       "Unusual burst of Git refs created",
			Description: "Multiple branches or tags appeared within one monitoring interval, which can indicate a coordinated or automated release campaign.",
			Evidence: fmt.Sprintf("created_branches=%d created_tags=%d threshold=%d",
				createdBranches, createdTags, m.options.BurstThreshold),
		})
	}
	latest := cloneSnapshot(current)
	m.previous = &latest
	slog.Debug("git refs observed", "findings", len(findings))
	return findings
}

func (m *Monitor) branchFindings(ctx context.Context, current Snapshot) []analyze.Finding {
	var findings []analyze.Finding
	for name, state := range current.Branches {
		previous, existed := m.previous.Branches[name]
		if !existed {
			m.branchFirst[name] = current.ObservedAt
			continue
		}
		if previous.SHA == state.SHA || strings.TrimSpace(previous.SHA) == "" || strings.TrimSpace(state.SHA) == "" {
			continue
		}
		findings = append(findings, analyze.Finding{
			ID: RefSHAChangedID, Severity: analyze.SeverityInformational,
			Title:       "Branch target changed",
			Description: "The monitored branch points to a new commit.",
			Evidence:    fmt.Sprintf("ref_type=branch ref=%s old_sha=%s new_sha=%s", name, previous.SHA, state.SHA),
		})
		if m.checkAncestry == nil {
			continue
		}
		fastForward, err := m.checkAncestry(ctx, name, previous.SHA, state.SHA)
		if err == nil && !fastForward {
			findings = append(findings, analyze.Finding{
				ID: RefNonFastForwardID, Severity: analyze.SeverityCritical,
				Title:       "Branch moved non-fast-forward",
				Description: "A monitored branch no longer descends from its prior commit, indicating history rewriting or force push.",
				Evidence:    fmt.Sprintf("ref_type=branch ref=%s old_sha=%s new_sha=%s", name, previous.SHA, state.SHA),
			})
		}
	}
	for name, previous := range m.previous.Branches {
		if _, exists := current.Branches[name]; exists {
			continue
		}
		firstSeen := m.branchFirst[name]
		lifetime := current.ObservedAt.Sub(firstSeen)
		if previous.HasRecentPipeline && !firstSeen.IsZero() && lifetime >= 0 && lifetime <= m.options.ShortLivedWindow {
			findings = append(findings, analyze.Finding{
				ID: ShortLivedCIBranchID, Severity: analyze.SeverityHigh,
				Title:       "Short-lived CI branch disappeared",
				Description: "A branch with a recently observed pipeline was created and removed within the configured short-lived window.",
				Evidence:    fmt.Sprintf("ref_type=branch ref=%s sha=%s lifetime=%s", name, previous.SHA, lifetime.Round(time.Second)),
			})
		}
		delete(m.branchFirst, name)
	}
	return findings
}

func (m *Monitor) tagFindings(current Snapshot) ([]analyze.Finding, int) {
	var findings []analyze.Finding
	created := 0
	for name, state := range current.Tags {
		previous, existed := m.previous.Tags[name]
		if existed && previous.SHA != state.SHA {
			findings = append(findings, analyze.Finding{
				ID: TagTargetChangedID, Severity: analyze.SeverityCritical,
				Title:       "Release tag target changed",
				Description: "An existing Git tag now resolves to a different commit, invalidating prior review or provenance assumptions.",
				Evidence:    fmt.Sprintf("ref_type=tag ref=%s old_sha=%s new_sha=%s", name, previous.SHA, state.SHA),
			})
			continue
		}
		if existed {
			continue
		}
		created++
		if deleted, recreated := m.deletedTags[name]; recreated {
			findings = append(findings, analyze.Finding{
				ID: TagRecreatedID, Severity: analyze.SeverityCritical,
				Title:       "Deleted release tag was recreated",
				Description: "A previously observed tag was deleted and recreated, which can redirect trusted publishing or release consumers.",
				Evidence:    fmt.Sprintf("ref_type=tag ref=%s deleted_sha=%s recreated_sha=%s", name, deleted.SHA, state.SHA),
			})
			delete(m.deletedTags, name)
		}
	}
	for name, previous := range m.previous.Tags {
		if _, exists := current.Tags[name]; exists {
			continue
		}
		m.deletedTags[name] = previous
		findings = append(findings, analyze.Finding{
			ID: TagDeletedID, Severity: analyze.SeverityHigh,
			Title:       "Monitored release tag was deleted",
			Description: "A previously observed Git tag disappeared. Deletion can precede recreation at a different release commit.",
			Evidence:    fmt.Sprintf("ref_type=tag ref=%s old_sha=%s", name, previous.SHA),
		})
	}
	return findings, created
}

// ReleaseWorkflowChanged reports whether publishing-job configuration differs.
func ReleaseWorkflowChanged(previous, current *pipeline.Document) bool {
	before := releaseJobFingerprints(previous)
	after := releaseJobFingerprints(current)
	if len(before) == 0 && len(after) == 0 {
		return false
	}
	return strings.Join(before, "\n") != strings.Join(after, "\n")
}

func releaseJobFingerprints(doc *pipeline.Document) []string {
	if doc == nil {
		return nil
	}
	var fingerprints []string
	for _, job := range doc.Jobs {
		rawJob, _ := doc.Raw[job.Name].(map[string]any)
		_, hasReleaseBlock := rawJob["release"]
		isPublishing := hasReleaseBlock
		for _, command := range job.Script {
			isPublishing = isPublishing || releaseCommandPattern.MatchString(strings.TrimSpace(command))
		}
		if !isPublishing {
			continue
		}
		encoded, err := json.Marshal(rawJob)
		if err != nil {
			continue
		}
		fingerprints = append(fingerprints, job.Name+":"+string(encoded))
	}
	sort.Strings(fingerprints)
	return fingerprints
}

func countNewRefs(previous, current map[string]RefState) int {
	count := 0
	for name := range current {
		if _, exists := previous[name]; !exists {
			count++
		}
	}
	return count
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	clone := Snapshot{
		ObservedAt: snapshot.ObservedAt,
		Branches:   make(map[string]RefState, len(snapshot.Branches)),
		Tags:       make(map[string]RefState, len(snapshot.Tags)),
	}
	for name, state := range snapshot.Branches {
		clone.Branches[name] = state
	}
	for name, state := range snapshot.Tags {
		clone.Tags[name] = state
	}
	return clone
}
