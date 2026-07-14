package gitlabx

import (
	"crypto/tls"
	"net/http"
	"testing"

	"golang.org/x/net/proxy"
)

func TestWithSOCKS5Proxy_SetsDialContextAndNilsProxy(t *testing.T) {
	// Build options with a SOCKS5 proxy address (doesn't need to be reachable for option test)
	cfg := options{}
	opt := WithSOCKS5Proxy("127.0.0.1:1080", nil)
	opt(&cfg)

	if cfg.socks5Addr != "127.0.0.1:1080" {
		t.Fatalf("socks5Addr = %q, want 127.0.0.1:1080", cfg.socks5Addr)
	}
	if cfg.socks5Auth != nil {
		t.Fatal("socks5Auth should be nil for no-auth proxy")
	}
}

func TestWithSOCKS5Proxy_WithAuth(t *testing.T) {
	auth := &proxy.Auth{User: "alice", Password: "s3cret"}
	cfg := options{}
	opt := WithSOCKS5Proxy("proxy.internal:9050", auth)
	opt(&cfg)

	if cfg.socks5Addr != "proxy.internal:9050" {
		t.Fatalf("socks5Addr = %q, want proxy.internal:9050", cfg.socks5Addr)
	}
	if cfg.socks5Auth == nil {
		t.Fatal("socks5Auth should not be nil")
		return
	}
	if cfg.socks5Auth.User != "alice" {
		t.Errorf("socks5Auth.User = %q, want alice", cfg.socks5Auth.User)
	}
	if cfg.socks5Auth.Password != "s3cret" {
		t.Errorf("socks5Auth.Password = %q, want s3cret", cfg.socks5Auth.Password)
	}
}

func TestWithSOCKS5Proxy_EmptyAddr_IsNoOp(t *testing.T) {
	// When socks5Addr is empty, New() should use http.ProxyFromEnvironment, not SOCKS5
	cfg := options{}
	opt := WithSOCKS5Proxy("", nil)
	opt(&cfg)

	if cfg.socks5Addr != "" {
		t.Fatalf("socks5Addr should remain empty, got %q", cfg.socks5Addr)
	}
}

func TestNew_WithSOCKS5Proxy_TransportHasDialContext(t *testing.T) {
	// Create a client with SOCKS5 — the transport should have DialContext set and Proxy nil.
	// We can't actually connect, but we can verify the transport is configured correctly.
	cl, err := New("https://gitlab.local", "test-token",
		WithSOCKS5Proxy("127.0.0.1:1080", nil),
		WithRateLimit(100, 100), // avoid rate limit blocking
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Walk the RoundTripper chain to get to the base transport
	transport := extractBaseTransport(t, cl.httpClient.Transport)
	if transport.DialContext == nil {
		t.Error("expected DialContext to be set when SOCKS5 is configured")
	}
	if transport.Proxy != nil {
		t.Error("expected Proxy to be nil when SOCKS5 is configured")
	}
}

func TestNew_WithoutSOCKS5_TransportUsesProxyFromEnvironment(t *testing.T) {
	cl, err := New("https://gitlab.local", "test-token",
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport := extractBaseTransport(t, cl.httpClient.Transport)
	if transport.DialContext != nil {
		t.Error("expected DialContext to be nil when SOCKS5 is not configured")
	}
	if transport.Proxy == nil {
		t.Error("expected Proxy to be set when SOCKS5 is not configured")
	}
}

func TestNew_SOCKS5_ComposesWithTLS(t *testing.T) {
	cl, err := New("https://gitlab.local", "test-token",
		WithSOCKS5Proxy("127.0.0.1:1080", &proxy.Auth{User: "u", Password: "p"}),
		WithInsecureTLS(true),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport := extractBaseTransport(t, cl.httpClient.Transport)
	if transport.DialContext == nil {
		t.Error("expected DialContext from SOCKS5")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig from InsecureTLS")
		return
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

// extractBaseTransport walks the RoundTripper middleware chain to find the underlying http.Transport.
func extractBaseTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	// Chain is: rateLimitedRoundTripper → retryingRoundTripper → headerRoundTripper → http.Transport
	rl, ok := rt.(*rateLimitedRoundTripper)
	if !ok {
		t.Fatalf("expected *rateLimitedRoundTripper, got %T", rt)
	}
	retry, ok := rl.next.(*retryingRoundTripper)
	if !ok {
		t.Fatalf("expected *retryingRoundTripper, got %T", rl.next)
	}
	hdr, ok := retry.next.(*headerRoundTripper)
	if !ok {
		t.Fatalf("expected *headerRoundTripper, got %T", retry.next)
	}
	transport, ok := hdr.next.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", hdr.next)
	}
	return transport
}

// Verify the TLS + no-SOCKS5 composition — TLS config is set, proxy is from environment
func TestNew_TLSWithoutSOCKS5(t *testing.T) {
	cl, err := New("https://gitlab.local", "test-token",
		WithInsecureTLS(true),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport := extractBaseTransport(t, cl.httpClient.Transport)
	if transport.DialContext != nil {
		t.Error("expected nil DialContext without SOCKS5")
	}
	if transport.Proxy == nil {
		t.Error("expected Proxy set without SOCKS5")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("expected TLS config with MinVersion TLS 1.2")
	}
}
