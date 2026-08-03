package refwatch

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestMonitorDetectsBranchRewriteAndSHAChange(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	monitor := NewMonitor(Options{}, func(_ context.Context, _, oldSHA, newSHA string) (bool, error) {
		return oldSHA == "old" && newSHA == "forward", nil
	})
	monitor.Observe(context.Background(), snapshotAt(now, map[string]RefState{
		"main": {SHA: "old"},
	}, nil))

	forward := monitor.Observe(context.Background(), snapshotAt(now.Add(time.Minute), map[string]RefState{
		"main": {SHA: "forward"},
	}, nil))
	if !hasFinding(forward, RefSHAChangedID) || hasFinding(forward, RefNonFastForwardID) {
		t.Fatalf("forward findings = %+v", forward)
	}

	rewritten := monitor.Observe(context.Background(), snapshotAt(now.Add(2*time.Minute), map[string]RefState{
		"main": {SHA: "rewritten"},
	}, nil))
	if !hasFinding(rewritten, RefNonFastForwardID) {
		t.Fatalf("rewrite findings = %+v", rewritten)
	}
}

func TestMonitorDetectsTagRetargetAndRecreation(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	monitor := NewMonitor(Options{}, nil)
	monitor.Observe(context.Background(), snapshotAt(now, nil, map[string]RefState{
		"v1.0.0": {SHA: "release-a"},
	}))

	retargeted := monitor.Observe(context.Background(), snapshotAt(now.Add(time.Minute), nil, map[string]RefState{
		"v1.0.0": {SHA: "release-b"},
	}))
	if !hasFinding(retargeted, TagTargetChangedID) {
		t.Fatalf("retarget findings = %+v", retargeted)
	}

	deleted := monitor.Observe(context.Background(), snapshotAt(now.Add(2*time.Minute), nil, nil))
	if !hasFinding(deleted, TagDeletedID) {
		t.Fatalf("delete findings = %+v", deleted)
	}

	recreated := monitor.Observe(context.Background(), snapshotAt(now.Add(3*time.Minute), nil, map[string]RefState{
		"v1.0.0": {SHA: "release-c"},
	}))
	if !hasFinding(recreated, TagRecreatedID) {
		t.Fatalf("recreate findings = %+v", recreated)
	}
}

func TestMonitorDetectsShortLivedCIBranchAndCreationBurst(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	monitor := NewMonitor(Options{ShortLivedWindow: 15 * time.Minute, BurstThreshold: 3}, nil)
	monitor.Observe(context.Background(), snapshotAt(now, map[string]RefState{
		"main": {SHA: "base"},
	}, nil))

	created := monitor.Observe(context.Background(), snapshotAt(now.Add(time.Minute), map[string]RefState{
		"main":     {SHA: "base"},
		"ci-check": {SHA: "one", HasRecentPipeline: true},
	}, map[string]RefState{
		"v1": {SHA: "one"}, "v2": {SHA: "two"}, "v3": {SHA: "three"},
	}))
	if !hasFinding(created, RefCreationBurstID) {
		t.Fatalf("creation findings = %+v", created)
	}

	removed := monitor.Observe(context.Background(), snapshotAt(now.Add(5*time.Minute), map[string]RefState{
		"main": {SHA: "base"},
	}, map[string]RefState{
		"v1": {SHA: "one"}, "v2": {SHA: "two"}, "v3": {SHA: "three"},
	}))
	if !hasFinding(removed, ShortLivedCIBranchID) {
		t.Fatalf("removed findings = %+v", removed)
	}
}

func TestReleaseWorkflowChanged(t *testing.T) {
	previous := parsePipeline(t, `
publish:
  script: [npm publish]
  rules:
    - if: '$CI_COMMIT_TAG'
`)
	current := parsePipeline(t, `
publish:
  script: [npm publish --access public]
  rules:
    - if: '$CI_COMMIT_TAG'
`)
	if !ReleaseWorkflowChanged(previous, current) {
		t.Fatal("expected release workflow change")
	}

	nonReleaseA := parsePipeline(t, "test:\n  script: [go test ./...]\n")
	nonReleaseB := parsePipeline(t, "test:\n  script: [go test -race ./...]\n")
	if ReleaseWorkflowChanged(nonReleaseA, nonReleaseB) {
		t.Fatal("non-release job change reported as release workflow change")
	}
}

func snapshotAt(at time.Time, branches, tags map[string]RefState) Snapshot {
	return Snapshot{ObservedAt: at, Branches: branches, Tags: tags}
}

func hasFinding(findings []analyze.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func parsePipeline(t *testing.T, source string) *pipeline.Document {
	t.Helper()
	doc, err := pipeline.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatalf("pipeline.Parse: %v", err)
	}
	return doc
}
