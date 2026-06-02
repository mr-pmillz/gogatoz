package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// fakeEnum emits each ident via Progress and returns the accumulated results.
func fakeEnum(t *testing.T) enumeratorFn {
	return func(_ context.Context, _ *gitlabx.Client, idents []string, opts enumerate.Options) ([]enumerate.Result, error) {
		var out []enumerate.Result
		for i, id := range idents {
			res := enumerate.Result{ProjectID: int64(100 + i), ProjectPathWithNS: id, WebURL: "https://example.com/" + id}
			if opts.Progress != nil {
				opts.Progress(res)
			}
			out = append(out, res)
			// tiny delay to exercise flushing
			time.Sleep(5 * time.Millisecond)
		}
		return out, nil
	}
}

func TestEnumerateStream_NDJSON(t *testing.T) {
	s := NewServer(Config{BaseURL: "https://gitlab.com"})
	// swap enumerator with fake to avoid hitting APIs
	s.enumFn = fakeEnum(t)

	ts := httptest.NewServer(s.engine)
	defer ts.Close()

	// build request body
	payload := map[string]any{
		"auth": map[string]any{
			"token":      "test-token",
			"gitlab_url": s.cfg.BaseURL,
		},
		"idents": []string{"g/a", "g/b"},
		"options": map[string]any{
			"concurrency": 2,
		},
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(ts.URL+"/enumerate/stream", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	// read NDJSON lines
	sc := bufio.NewScanner(resp.Body)
	var lines []string
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln != "" {
			lines = append(lines, ln)
			if len(lines) >= 2 { // we expect two results, ok to stop early
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	// validate JSON objects
	for _, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("invalid json line: %v (err=%v)", ln, err)
		}
		if _, ok := m["path_with_namespace"]; !ok {
			t.Fatalf("missing path_with_namespace: %v", m)
		}
	}
}
