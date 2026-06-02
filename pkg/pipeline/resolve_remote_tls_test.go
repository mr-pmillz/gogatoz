package pipeline

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// This test verifies that remote include fetching against a self-signed TLS server
// fails by default and succeeds when the client is configured with Insecure TLS.
func TestRemoteIncludeSelfSignedTLS_InsecureToggle(t *testing.T) {
	// Build a TLS test server (self-signed cert)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ci.yml" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("stages: [build]\njob1:\n  script: ['echo hi']\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	incDoc := &Document{Includes: []Include{{Type: IncludeRemote, Remote: ts.URL + "/ci.yml"}}}
	ctx := context.Background()

	// Case 1: default client (no insecure, no custom CA) => expect partial error due to cert
	cl1, err := gitlabx.New(ts.URL, "")
	if err != nil {
		t.Fatalf("client new: %v", err)
	}
	_, err = ResolveIncludesWithOptions(ctx, cl1, 0, "", incDoc, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
		RemoteMaxBytes:   0,
		RemoteTimeout:    2 * time.Second,
	})
	if err == nil {
		t.Fatalf("expected partial error due to TLS verify failure, got nil")
	}

	// Sanity: ensure the client's transport honors InsecureSkipVerify when set.
	// Case 2: insecure=true => should succeed
	cl2, err := gitlabx.New(ts.URL, "", gitlabx.WithInsecureTLS(true))
	if err != nil {
		t.Fatalf("client new insecure: %v", err)
	}
	// Also verify transport indeed has InsecureSkipVerify true by attempting a direct request
	// to the TLS server; if not, RoundTrip would fail. We'll do that implicitly via resolver.
	merged, err := ResolveIncludesWithOptions(ctx, cl2, 0, "", incDoc, 1, ResolveOptions{
		AllowRemote:      true,
		RemoteAllowHosts: []string{u.Host},
		RemoteMaxBytes:   0,
		RemoteTimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error with insecure TLS: %v", err)
	}
	if merged == nil || len(merged.Jobs) != 1 || len(merged.Stages) != 1 {
		t.Fatalf("expected merged doc with 1 job and build stage, got %+v", merged)
	}

	// Additional guard: ensure server actually used TLS
	if ts.TLS == nil || ts.TLS.Certificates == nil || len(ts.TLS.Certificates) == 0 {
		t.Fatalf("test server is not TLS-enabled")
	}
	_ = tls.VersionTLS12 // reference to avoid unused in case of build quirks
}
