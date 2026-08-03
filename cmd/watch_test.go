package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/refwatch"
)

func TestConvertRefSnapshot(t *testing.T) {
	observed := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	converted := convertRefSnapshot(gitlabx.RefSnapshot{
		ObservedAt: observed,
		Branches: map[string]gitlabx.RefState{
			"main": {SHA: "abc", HasRecentPipeline: true},
		},
		Tags: map[string]gitlabx.RefState{"v1": {SHA: "abc"}},
	})
	if !converted.ObservedAt.Equal(observed) || !converted.Branches["main"].HasRecentPipeline ||
		converted.Tags["v1"].SHA != "abc" {
		t.Fatalf("converted = %+v", converted)
	}
}

func TestPollAndAnalyzeDetectsReleaseWorkflowChange(t *testing.T) {
	sources := []string{
		"publish:\n  script: [npm publish]\n  rules:\n    - if: '$CI_COMMIT_TAG'\n",
		"publish:\n  script: [npm publish --access public]\n  rules:\n    - if: '$CI_COMMIT_TAG'\n",
	}
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		index := requestCount
		if index >= len(sources) {
			index = len(sources) - 1
		}
		requestCount++
		content := base64.StdEncoding.EncodeToString([]byte(sources[index]))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"file_name":".gitlab-ci.yml","file_path":".gitlab-ci.yml","encoding":"base64","content":%q,"commit_id":"sha-%d","last_commit_id":"sha-%d","ref":"main"}`,
			content, index, index)
	}))
	defer srv.Close()
	client, err := gitlabx.New(srv.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	lastSHA := map[string]string{}
	lastDocs := map[string]*pipeline.Document{}
	_ = pollAndAnalyze(context.Background(), client, "42", "main", lastSHA, lastDocs)
	findings := pollAndAnalyze(context.Background(), client, "42", "main", lastSHA, lastDocs)
	if !watchFindingsContain(findings, refwatch.ReleaseWorkflowChangedID) {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestWriteWatchAlertSupportsTextAndJSON(t *testing.T) {
	alert := watchAlert{
		Time: "2026-07-31T12:00:00Z", Project: "group/project", Branch: "main",
		Findings: []analyze.Finding{{ID: refwatch.TagTargetChangedID, Severity: analyze.SeverityCritical, Title: "tag changed"}},
	}
	var textOutput bytes.Buffer
	if err := writeWatchAlert(&textOutput, alert, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOutput.String(), refwatch.TagTargetChangedID) {
		t.Fatalf("text output = %q", textOutput.String())
	}

	var jsonOutput bytes.Buffer
	if err := writeWatchAlert(&jsonOutput, alert, "json"); err != nil {
		t.Fatal(err)
	}
	var decoded watchAlert
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatalf("json output = %q: %v", jsonOutput.String(), err)
	}
	if decoded.Project != alert.Project || len(decoded.Findings) != 1 {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func watchFindingsContain(findings []analyze.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
