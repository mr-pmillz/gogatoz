package pipeline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

const benchIncludeChildYAML = `
stages: [lint]
lint_job:
  stage: lint
  script:
    - echo "linting..."
  tags: [docker]
`

func BenchmarkResolveIncludes(b *testing.B) {
	encoded := base64.StdEncoding.EncodeToString([]byte(benchIncludeChildYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve repository files API: GET /api/v4/projects/:id/repository/files/:path
		if strings.Contains(r.URL.Path, "/repository/files/") {
			resp := map[string]any{
				"file_name": "child.yml",
				"file_path": ".gitlab/ci/child.yml",
				"encoding":  "base64",
				"content":   encoded,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	cl, err := gitlabx.New(ts.URL, "test-token")
	if err != nil {
		b.Fatalf("gitlabx.New: %v", err)
	}

	base := &Document{
		Stages: []string{"build"},
		Includes: []Include{
			{Type: IncludeLocal, Local: ".gitlab/ci/child.yml"},
			{Type: IncludeLocal, Local: ".gitlab/ci/security.yml"},
		},
		Jobs: []Job{
			{Name: "build", Stage: "build", Script: []string{"echo build"}},
		},
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merged, rerr := ResolveIncludesWithOptions(ctx, cl, int64(1), "main", base, 2, ResolveOptions{})
		if rerr != nil {
			// Partial errors are expected for the second include (same content served)
			// but should not be fatal
			_ = rerr
		}
		if merged == nil {
			b.Fatal("expected merged document")
		}
	}
}
