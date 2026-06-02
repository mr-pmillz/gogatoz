package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRemoteIncludeAllowedSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ci.yml" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("stages: [build]\njob1:\n  script: ['echo hi']\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	base := &Document{Includes: []Include{{Type: IncludeRemote, Remote: ts.URL + "/ci.yml"}}}
	ctx := context.Background()
	merged, err := ResolveIncludesWithOptions(ctx, nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
		RemoteMaxBytes:   0,
		RemoteTimeout:    2 * time.Second,
	})
	if err != nil {
		// Should not error for allowed case
		t.Fatalf("unexpected error: %v", err)
	}
	if merged == nil {
		t.Fatalf("expected merged document, got nil")
	}
	if len(merged.Jobs) != 1 {
		t.Fatalf("expected 1 job from remote include, got %d", len(merged.Jobs))
	}
	if len(merged.Stages) != 1 || merged.Stages[0] != stageBuild {
		t.Fatalf("expected stages ['build'], got %v", merged.Stages)
	}
}

func TestRemoteIncludeDisallowedHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("stages: [test]\n"))
	}))
	defer ts.Close()
	base := &Document{Includes: []Include{{Type: IncludeRemote, Remote: ts.URL}}}
	ctx := context.Background()
	merged, err := ResolveIncludesWithOptions(ctx, nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{"example.com"}, // does not include httptest host
		RemoteMaxBytes:   0,
		RemoteTimeout:    1 * time.Second,
	})
	if err == nil {
		t.Fatalf("expected partial error due to disallowed host, got nil")
	}
	if !strings.Contains(err.Error(), "host not allowed") {
		t.Fatalf("expected error to mention host not allowed, got: %v", err)
	}
	if merged == nil {
		t.Fatalf("expected merged document (original), got nil")
	}
	if len(merged.Jobs) != 0 {
		t.Fatalf("expected 0 jobs since include not fetched, got %d", len(merged.Jobs))
	}
}

func TestRemoteIncludeSizeLimit(t *testing.T) {
	// Create content larger than 32 bytes
	content := strings.Repeat("a", 64)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	base := &Document{Includes: []Include{{Type: IncludeRemote, Remote: ts.URL}}}
	ctx := context.Background()
	_, err := ResolveIncludesWithOptions(ctx, nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
		RemoteMaxBytes:   32,
		RemoteTimeout:    1 * time.Second,
	})
	if err == nil {
		t.Fatalf("expected partial error due to size limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max bytes") {
		t.Fatalf("expected error to mention exceeds max bytes, got: %v", err)
	}
}
