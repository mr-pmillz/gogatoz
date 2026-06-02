package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteIncludeTTLCachingAcrossCalls(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("stages: [build]\njob1:\n  script: ['echo hi']\n"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	base := &Document{Includes: []Include{{Type: IncludeRemote, Remote: ts.URL + "/ci.yml"}}}
	ctx := context.Background()

	// Clear any previous cache entries that may interfere with this test
	remoteCacheMu.Lock()
	for k := range remoteCache {
		delete(remoteCache, k)
	}
	remoteCacheMu.Unlock()

	// First call should fetch from network (hits=1)
	merged1, err := ResolveIncludesWithOptions(ctx, nil, 0, "", base, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
		RemoteMaxBytes:   0,
		RemoteTimeout:    2 * time.Second,
		RemoteCacheTTL:   5 * time.Minute,
	})
	if err != nil {
		// allow partial errors but we expect success here
		t.Fatalf("unexpected error: %v", err)
	}
	if merged1 == nil || len(merged1.Jobs) != 1 {
		t.Fatalf("expected merged doc with 1 job, got %+v", merged1)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 network hit after first call, got %d", got)
	}

	// Second call with a new base document should use TTL cache (hits still 1)
	base2 := &Document{Includes: []Include{{Type: IncludeRemote, Remote: ts.URL + "/ci.yml"}}}
	merged2, err := ResolveIncludesWithOptions(ctx, nil, 0, "", base2, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
		RemoteMaxBytes:   0,
		RemoteTimeout:    2 * time.Second,
		RemoteCacheTTL:   5 * time.Minute,
	})
	if err != nil {
		// should still be ok
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if merged2 == nil || len(merged2.Jobs) != 1 {
		t.Fatalf("expected merged doc with 1 job on second call, got %+v", merged2)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected no additional network hit due to TTL cache, got %d", got)
	}
}
