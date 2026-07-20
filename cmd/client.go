package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// buildClientOptions returns the standard gitlabx.Option slice derived from
// the global CLI flags (rate limiting, retry, user-agent, HTTP pool/timeouts,
// TLS, CA cert, SOCKS5 proxy).
func buildClientOptions() ([]gitlabx.Option, error) {
	opts := []gitlabx.Option{
		gitlabx.WithRateLimit(rateRPS, rateBurst),
		gitlabx.WithRetry(retryMax),
	}

	if ua := strings.TrimSpace(userAgent); ua != "" {
		opts = append(opts, gitlabx.WithUserAgent(ua))
	}

	var idleTO, tlsTO, expectTO, reqTO time.Duration
	if s := strings.TrimSpace(httpIdleTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid --http-idle-timeout: %w", err)
		}
		idleTO = d
	}
	if s := strings.TrimSpace(httpTLSTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid --http-tls-timeout: %w", err)
		}
		tlsTO = d
	}
	if s := strings.TrimSpace(httpExpectTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid --http-expect-timeout: %w", err)
		}
		expectTO = d
	}
	if s := strings.TrimSpace(httpRequestTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid --http-req-timeout: %w", err)
		}
		reqTO = d
	}
	if httpMaxIdle > 0 || httpMaxIdlePerHost > 0 {
		opts = append(opts, gitlabx.WithHTTPPool(httpMaxIdle, httpMaxIdlePerHost))
	}
	if idleTO > 0 || tlsTO > 0 || expectTO > 0 || reqTO > 0 {
		opts = append(opts, gitlabx.WithHTTPTimeouts(idleTO, tlsTO, expectTO, reqTO))
	}
	if insecureSkipTLS {
		opts = append(opts, gitlabx.WithInsecureTLS(true))
	}
	if p := strings.TrimSpace(caCertPath); p != "" {
		pem, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read --ca-cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-cert: no valid PEM certificates found")
		}
		opts = append(opts, gitlabx.WithRootCAs(pool))
	}
	opts = appendSOCKS5Option(opts)
	return opts, nil
}

// newGitLabClient creates a gitlabx.Client using the global CLI flags.
func newGitLabClient() (*gitlabx.Client, error) {
	opts, err := buildClientOptions()
	if err != nil {
		return nil, err
	}
	return gitlabx.New(strings.TrimSpace(gitlabURL), token, opts...)
}
