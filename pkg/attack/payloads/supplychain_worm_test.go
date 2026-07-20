package payloads

import (
	"testing"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestEligibleWormSibling(t *testing.T) {
	t.Parallel()

	deletionDate := gitlab.ISOTime(time.Now())
	tests := []struct {
		name    string
		project *gitlab.Project
		want    bool
	}{
		{name: "live sibling", project: &gitlab.Project{PathWithNamespace: "group/sibling"}, want: true},
		{name: "target", project: &gitlab.Project{PathWithNamespace: "group/target"}},
		{name: "scheduled for deletion", project: &gitlab.Project{PathWithNamespace: "group/old", MarkedForDeletionOn: &deletionDate}},
		{name: "nil project"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := eligibleWormSibling(tt.project, "group/target"); got != tt.want {
				t.Fatalf("eligibleWormSibling() = %t, want %t", got, tt.want)
			}
		})
	}
}
