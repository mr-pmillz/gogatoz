package payloads

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestGenerateJobTokenPushYAML(t *testing.T) {
	yaml := GenerateJobTokenPushYAML(JobTokenPushOptions{
		Common: CommonOptions{JobName: "token-push", Manual: true},
	})
	doc, err := pipeline.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("generated YAML did not parse: %v\n%s", err, yaml)
	}
	if len(doc.Jobs) != 1 || doc.Jobs[0].Name != "token-push" {
		t.Fatalf("unexpected generated jobs: %+v", doc.Jobs)
	}
	for _, required := range []string{
		"CI_JOB_TOKEN",
		"gitlab-ci-token",
		"refs/heads/$_TARGET_BRANCH",
		"result=push_succeeded",
		"result=push_denied",
		"when: always",
		"env_dump.txt",
		"job_token_push_report.txt",
		"[REDACTED]",
	} {
		if !strings.Contains(yaml, required) {
			t.Fatalf("generated payload missing %q:\n%s", required, yaml)
		}
	}
}
