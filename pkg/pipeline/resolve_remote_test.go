package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
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
		return
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
		return
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

func TestResolveIncludes_PreservesRootGlobalConfiguration(t *testing.T) {
	included := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("included-job:\n  script: [echo included]\n"))
	}))
	defer included.Close()
	u, _ := url.Parse(included.URL)

	base, err := Parse(strings.NewReader(`default:
  image: alpine:3.20
  cache:
    key: root-cache
before_script:
  - echo root-before
after_script:
  - echo root-after
root-job:
  script: [echo root]
`))
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	base.Includes = []Include{{Type: IncludeRemote, Remote: included.URL}}
	merged, err := ResolveIncludesWithOptions(context.Background(), nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if merged.Default["image"] != "alpine:3.20" {
		t.Fatalf("root default was lost: %#v", merged.Default)
	}
	if len(merged.BeforeScript) != 1 || merged.BeforeScript[0] != "echo root-before" {
		t.Fatalf("root before_script was lost: %v", merged.BeforeScript)
	}
	if len(merged.AfterScript) != 1 || merged.AfterScript[0] != "echo root-after" {
		t.Fatalf("root after_script was lost: %v", merged.AfterScript)
	}
	if len(merged.Cache) != 1 || merged.Cache[0]["key"] != "root-cache" {
		t.Fatalf("root cache was lost: %#v", merged.Cache)
	}
}

func TestResolveIncludes_MergesIncludedGlobalConfiguration(t *testing.T) {
	included := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`default:
  image: alpine:3.20
before_script:
  - echo included-before
after_script:
  - echo included-after
cache:
  key: included-cache
included-job:
  script: [echo included]
`))
	}))
	defer included.Close()
	u, _ := url.Parse(included.URL)
	base := &Document{Includes: []Include{{Type: IncludeRemote, Remote: included.URL}}}

	merged, err := ResolveIncludesWithOptions(context.Background(), nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if merged.Default["image"] != "alpine:3.20" ||
		len(merged.BeforeScript) != 1 || len(merged.AfterScript) != 1 ||
		len(merged.Cache) != 1 || merged.Cache[0]["key"] != "included-cache" {
		t.Fatalf("included globals were not merged: %#v", merged)
	}
}

func TestRemoteInclude_RedirectTargetMustBeAllowlisted(t *testing.T) {
	var blockedHits atomic.Int64
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		blockedHits.Add(1)
		_, _ = w.Write([]byte("job:\n  script: [echo should-not-run]\n"))
	}))
	defer blocked.Close()

	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, blocked.URL+"/ci.yml", http.StatusFound)
	}))
	defer allowed.Close()
	allowedURL, _ := url.Parse(allowed.URL)
	base := &Document{Includes: []Include{{Type: IncludeRemote, Remote: allowed.URL}}}

	_, err := ResolveIncludesWithOptions(context.Background(), nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{allowedURL.Host},
	})
	if err == nil || !strings.Contains(err.Error(), "redirect host not allowed") {
		t.Fatalf("expected redirect allowlist error, got %v", err)
	}
	if blockedHits.Load() != 0 {
		t.Fatalf("disallowed redirect target received %d requests", blockedHits.Load())
	}
}

func TestResolveIncludes_LocalWithoutClientReturnsPartialError(t *testing.T) {
	base := &Document{Includes: []Include{{Type: IncludeLocal, Local: "/child.yml"}}}
	merged, err := ResolveIncludesWithOptions(context.Background(), nil, 1, "main", base, 1, ResolveOptions{})
	if merged == nil || err == nil || !strings.Contains(err.Error(), "missing GitLab client") {
		t.Fatalf("expected safe partial result, merged=%v err=%v", merged, err)
	}
}
