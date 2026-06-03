package enumerate

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

const benchCIYAML = `
stages: [build, test]
build:
  stage: build
  script:
    - echo "building"
  tags: [docker]
test:
  stage: test
  script:
    - echo "testing"
  needs: [build]
`

func BenchmarkEnumerateProjects(b *testing.B) {
	ciEncoded := base64.StdEncoding.EncodeToString([]byte(benchCIYAML))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// GET /api/v4/projects/:id — return project metadata
		if strings.Contains(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
			resp := map[string]any{
				"id":                  int64(42),
				"path_with_namespace": "group/bench-project",
				"web_url":             "https://gitlab.local/group/bench-project",
				"default_branch":      "main",
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// GET /api/v4/projects/:id/repository/files/:path — return CI file
		if strings.Contains(r.URL.Path, "/repository/files/") {
			resp := map[string]any{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"encoding":  "base64",
				"content":   ciEncoded,
			}
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

	idents := []string{"42"}
	opts := Options{
		Concurrency: 2,
		SkipAnalyze: false,
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, rerr := EnumerateProjects(ctx, cl, idents, opts)
		if rerr != nil {
			b.Fatalf("enumerate: %v", rerr)
		}
		if len(results) == 0 {
			b.Fatal("expected results")
		}
	}
}
