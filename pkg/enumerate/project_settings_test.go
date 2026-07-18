package enumerate

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestProjectSettingFindings(t *testing.T) {
	project := &gitlab.Project{
		Visibility:                               gitlab.PrivateVisibility,
		CIPushRepositoryForJobTokenAllowed:       true,
		CIAllowForkPipelinesToRunInParentProject: true,
		PublicJobs:                               true,
	}
	findings := projectSettingFindings(project)
	want := map[string]analyze.Severity{
		JobTokenPushEnabledID:       analyze.SeverityHigh,
		ForkPipelineParentEnabledID: analyze.SeverityHigh,
		PublicPipelineJobsID:        analyze.SeverityMedium,
	}
	if len(findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(findings), len(want), findings)
	}
	for _, finding := range findings {
		if severity, ok := want[finding.ID]; !ok || finding.Severity != severity {
			t.Fatalf("unexpected finding: %+v", finding)
		}
	}
}

func TestProjectSettingFindings_DefaultsAreQuiet(t *testing.T) {
	if findings := projectSettingFindings(&gitlab.Project{}); len(findings) != 0 {
		t.Fatalf("zero-value project produced findings: %+v", findings)
	}
	if findings := projectSettingFindings(nil); len(findings) != 0 {
		t.Fatalf("nil project produced findings: %+v", findings)
	}
}
