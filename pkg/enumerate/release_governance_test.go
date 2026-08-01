package enumerate

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestEvaluateReleaseGovernanceFlagsWeakReleaseRefs(t *testing.T) {
	doc := parseReleaseGovernanceFixture(t, `
publish:
  stage: release
  script: [npm publish]
  rules:
    - if: '$CI_COMMIT_BRANCH == "next"'
    - if: '$CI_COMMIT_TAG'
`)
	snapshot := releaseProtectionSnapshot{
		branches: []gitlabx.BranchProtectionDetail{{
			Name: "next", PushAccessLevel: 30, MergeAccessLevel: 30,
			CodeOwnerApprovalNeeded: false,
		}},
	}

	findings := evaluateReleaseGovernance(doc, "main", snapshot)
	for _, findingID := range []string{ReleaseBranchWeakProtectionID, ReleaseTagWeakProtectionID} {
		if !releaseFindingsContain(findings, findingID) {
			t.Errorf("findings %+v missing %s", findings, findingID)
		}
	}
}

func TestEvaluateReleaseGovernanceFlagsBroadReleaseJob(t *testing.T) {
	doc := parseReleaseGovernanceFixture(t, `
publish:
  stage: release
  release:
    tag_name: $CI_COMMIT_TAG
  script: [release-cli create]
`)

	findings := evaluateReleaseGovernance(doc, "main", releaseProtectionSnapshot{})
	if !releaseFindingsContain(findings, ReleaseJobBroadTriggerID) {
		t.Fatalf("findings %+v missing %s", findings, ReleaseJobBroadTriggerID)
	}
}

func TestEvaluateReleaseGovernanceAcceptsReviewedReleasePath(t *testing.T) {
	doc := parseReleaseGovernanceFixture(t, `
publish:
  stage: release
  script: [gem push package.gem]
  rules:
    - if: '$CI_COMMIT_BRANCH == "next"'
    - if: '$CI_COMMIT_TAG =~ /^v/'
`)
	snapshot := releaseProtectionSnapshot{
		branches: []gitlabx.BranchProtectionDetail{{
			Name: "next", PushAccessLevel: 0, MergeAccessLevel: 40,
			CodeOwnerApprovalNeeded: true,
		}},
		tags: []gitlabx.TagProtectionDetail{{Name: "v*", CreateAccessLevel: 40}},
	}

	findings := evaluateReleaseGovernance(doc, "main", snapshot)
	for _, finding := range findings {
		switch finding.ID {
		case ReleaseBranchWeakProtectionID, ReleaseTagWeakProtectionID, ReleaseJobBroadTriggerID:
			t.Fatalf("unexpected release governance finding: %+v", finding)
		}
	}
}

func TestExtractReleaseTriggersHandlesOnlySyntax(t *testing.T) {
	doc := parseReleaseGovernanceFixture(t, `
publish:
  script: [twine upload dist/*]
  only: [stable, tags]
`)
	triggers := extractReleaseTriggers(doc.Jobs[0], doc, "main")
	if len(triggers.branches) != 1 || triggers.branches[0] != "stable" || !triggers.tags {
		t.Fatalf("triggers = %+v", triggers)
	}
}

func parseReleaseGovernanceFixture(t *testing.T, yaml string) *pipeline.Document {
	t.Helper()
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("pipeline.Parse: %v", err)
	}
	return doc
}

func releaseFindingsContain(findings []analyze.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
