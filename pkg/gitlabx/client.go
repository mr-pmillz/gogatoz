package gitlabx

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// normalizeBaseURL ensures the provided base URL is suitable for composing GitLab API endpoints.
// It accepts inputs like:
//   - gitlab.example.com
//   - https://gitlab.example.com
//   - https://gitlab.example.com/
//   - https://gitlab.example.com/api/v4
//   - https://gitlab.example.com/gitlab (GitLab behind subpath)
//   - https://gitlab.example.com/gitlab/api/v4
//
// It returns a URL without trailing slash and without the /api or /api/v4 suffix, preserving any
// additional subpath if present. If the input lacks a scheme, https:// is assumed.
func normalizeBaseURL(in string) (string, error) {
	v := strings.TrimSpace(in)
	if v == "" {
		return "", fmt.Errorf("empty baseURL")
	}
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", err
	}
	// Clean path: strip trailing slashes and any trailing /api or /api/v4 segments
	p := strings.TrimRight(u.Path, "/")
	for {
		if strings.HasSuffix(p, "/api/v4") {
			p = strings.TrimSuffix(p, "/api/v4")
			p = strings.TrimRight(p, "/")
			continue
		}
		if strings.HasSuffix(p, "/api") {
			p = strings.TrimSuffix(p, "/api")
			p = strings.TrimRight(p, "/")
			continue
		}
		break
	}
	u.Path = p
	u.RawQuery = ""
	u.Fragment = ""
	out := strings.TrimRight(u.String(), "/")
	return out, nil
}

// Client wraps the official GitLab client and provides minimal extras we need across commands.
type Client struct {
	GL         *gitlab.Client
	ratelimit  *rate.Limiter
	httpClient *http.Client
	baseURL    string
	token      string
}

// GraphQLResponse models a minimal GitLab GraphQL response structure.
// See https://docs.gitlab.com/ee/api/graphql/
// Data is left as raw JSON for callers to decode as needed.
// If Errors is non-empty, GraphQL returns HTTP 200 but the request failed logically.
// In that case, GraphQL returns an "errors" array with message fields.
// We surface those as an error.
// NOTE: This helper intentionally keeps a small surface and avoids bringing an external GraphQL client.
//
//nolint:tagliatelle // GraphQL uses snake_case keys
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// HTTPClient returns the underlying tuned HTTP client used for API calls.
func (c *Client) HTTPClient() *http.Client { return c.httpClient }

// APIURL composes a full API URL from a relative path (starting with /api/v4...).
// If rel is an absolute URL, it is returned as-is.
func (c *Client) APIURL(rel string) string {
	if strings.HasPrefix(rel, "http://") || strings.HasPrefix(rel, "https://") {
		return rel
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return c.baseURL + rel
}

// Token returns the private token configured on this client (may be empty).
func (c *Client) Token() string { return c.token }

// Option allows customizing the client.
type Option func(*options)

// WithInsecureTLS skips certificate verification (for testing or self-hosted instances with self-signed certs).
func WithInsecureTLS(skip bool) Option { return func(o *options) { o.insecureSkipVerify = skip } }

// WithRootCAs sets a custom root CA pool for TLS verification.
func WithRootCAs(pool *x509.CertPool) Option { return func(o *options) { o.rootCAs = pool } }

// WithSOCKS5Proxy routes all connections through a SOCKS5 proxy.
// addr is "host:port". auth is optional (nil for no authentication).
// When set, replaces http.ProxyFromEnvironment — HTTP_PROXY/HTTPS_PROXY env vars are ignored.
func WithSOCKS5Proxy(addr string, auth *proxy.Auth) Option {
	return func(o *options) {
		o.socks5Addr = addr
		o.socks5Auth = auth
	}
}

type options struct {
	userAgent string
	rateRPS   float64
	burst     int
	retryMax  int
	retryBase time.Duration
	retryMaxD time.Duration
	// HTTP pooling and timeouts
	maxIdleConns          int
	maxIdlePerHost        int
	idleConnTimeout       time.Duration
	tlsHandshakeTimeout   time.Duration
	expectContinueTimeout time.Duration
	reqTimeout            time.Duration
	// TLS controls for self-hosted/internal GitLab
	insecureSkipVerify bool
	rootCAs            *x509.CertPool
	// SOCKS5 proxy
	socks5Addr string
	socks5Auth *proxy.Auth
}

// WithUserAgent sets a custom user agent string.
func WithUserAgent(ua string) Option { return func(o *options) { o.userAgent = ua } }

// WithRateLimit configures a simple token bucket rate limiter (requests per second and burst).
func WithRateLimit(rps float64, burst int) Option {
	return func(o *options) {
		o.rateRPS = rps
		o.burst = burst
	}
}

// WithRetry configures retry attempts and backoff. Set maxAttempts<=1 to disable retries.
func WithRetry(maxAttempts int) Option {
	return func(o *options) {
		o.retryMax = maxAttempts
	}
}

// WithHTTPPool configures HTTP connection pooling sizes.
func WithHTTPPool(maxIdle, perHost int) Option {
	return func(o *options) {
		if maxIdle > 0 {
			o.maxIdleConns = maxIdle
		}
		if perHost > 0 {
			o.maxIdlePerHost = perHost
		}
	}
}

// WithHTTPTimeouts configures transport and request timeouts.
func WithHTTPTimeouts(idleConn, tlsHandshake, expectContinue, request time.Duration) Option {
	return func(o *options) {
		if idleConn > 0 {
			o.idleConnTimeout = idleConn
		}
		if tlsHandshake > 0 {
			o.tlsHandshakeTimeout = tlsHandshake
		}
		if expectContinue > 0 {
			o.expectContinueTimeout = expectContinue
		}
		if request > 0 {
			o.reqTimeout = request
		}
	}
}

// New returns a new Client. baseURL like "https://gitlab.com" (no trailing slash). token is a PAT.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	cfg := options{
		userAgent: defaultUserAgent(),
		rateRPS:   8, // sane default; GitLab defaults vary by plan, keep conservative
		burst:     16,
		retryMax:  3,
		retryBase: 200 * time.Millisecond,
		retryMaxD: 2 * time.Second,
		// HTTP defaults
		maxIdleConns:          256,
		maxIdlePerHost:        64,
		idleConnTimeout:       90 * time.Second,
		tlsHandshakeTimeout:   10 * time.Second,
		expectContinueTimeout: 1 * time.Second,
		reqTimeout:            30 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// Build tuned base transport
	// TLS config supports internal/self-hosted instances with custom CAs or self-signed certs (opt-in)
	var tlsCfg *tls.Config
	if cfg.insecureSkipVerify || cfg.rootCAs != nil {
		// Intentionally allow InsecureSkipVerify only when explicitly configured for testing/self-hosted setups.
		// This is guarded by a user-provided flag and is not enabled by default. #nosec G402
		tlsCfg = &tls.Config{InsecureSkipVerify: cfg.insecureSkipVerify, MinVersion: tls.VersionTLS12} //nolint:gosec
		if cfg.rootCAs != nil {
			tlsCfg.RootCAs = cfg.rootCAs
		}
	}
	// SOCKS5 proxy: when configured, replace the default dialer with a SOCKS5 tunnel.
	// This routes all TCP connections through the proxy, replacing HTTP_PROXY/HTTPS_PROXY.
	var dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	var httpProxy func(*http.Request) (*url.URL, error)
	if cfg.socks5Addr != "" {
		fwd := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dialer, err := proxy.SOCKS5("tcp", cfg.socks5Addr, cfg.socks5Auth, fwd)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy: %w", err)
		}
		ctxDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 dialer does not support DialContext")
		}
		dialCtx = ctxDialer.DialContext
	} else {
		httpProxy = http.ProxyFromEnvironment
	}

	baseTransport := &http.Transport{
		Proxy:                 httpProxy,
		DialContext:           dialCtx,
		MaxIdleConns:          cfg.maxIdleConns,
		MaxIdleConnsPerHost:   cfg.maxIdlePerHost,
		IdleConnTimeout:       cfg.idleConnTimeout,
		TLSHandshakeTimeout:   cfg.tlsHandshakeTimeout,
		ExpectContinueTimeout: cfg.expectContinueTimeout,
		TLSClientConfig:       tlsCfg,
	}

	// Compose RoundTrippers: header -> retry -> rate limit -> transport
	hdr := &headerRoundTripper{next: baseTransport, headers: map[string]string{"User-Agent": cfg.userAgent}}
	rty := &retryingRoundTripper{next: hdr, maxAttempts: cfg.retryMax, baseDelay: cfg.retryBase, maxDelay: cfg.retryMaxD}
	lim := rate.NewLimiter(rate.Limit(cfg.rateRPS), cfg.burst)
	rt := &rateLimitedRoundTripper{next: rty, lim: lim}

	hc := &http.Client{Transport: rt, Timeout: cfg.reqTimeout}

	// Normalize base URL and configure official client to point to the REST base.
	norm, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	gl, err := gitlab.NewClient(token, gitlab.WithBaseURL(norm+"/api/v4"), gitlab.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	return &Client{GL: gl, ratelimit: lim, httpClient: hc, baseURL: norm, token: token}, nil
}

// headerRoundTripper injects static headers into every request.
type headerRoundTripper struct {
	next    http.RoundTripper
	headers map[string]string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	return h.next.RoundTrip(req)
}

// retryingRoundTripper retries on 429 and transient 5xx with jittered exponential backoff.
type retryingRoundTripper struct {
	next        http.RoundTripper
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

// RoundTrip ...
//
//nolint:gocognit
func (r *retryingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := r.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	var resp *http.Response
	var err error
	for i := 1; i <= attempts; i++ {
		resp, err = r.next.RoundTrip(req)
		if err != nil {
			// Network error: retry unless last attempt
			if i == attempts {
				return resp, err
			}
		} else {
			// If response status is not retryable, return immediately
			if !isRetryable(resp.StatusCode) {
				return resp, nil
			}
			// Close body before next attempt to avoid leaks
			_ = resp.Body.Close()
			if i == attempts {
				return resp, nil
			}
		}
		// Compute backoff
		delay := r.baseDelay
		if delay <= 0 {
			delay = 200 * time.Millisecond
		}
		// Exponential growth
		for j := 1; j < i; j++ {
			delay *= 2
		}
		if r.maxDelay > 0 && delay > r.maxDelay {
			delay = r.maxDelay
		}
		// Honor Retry-After header if present and parseable
		if resp != nil {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, perr := strconv.Atoi(ra); perr == nil {
					delay = time.Duration(secs) * time.Second
				}
			}
		}
		var wait time.Duration
		if delay > 0 {
			// Add jitter +/- 25% using crypto/rand for security lint compliance
			maxInt := big.NewInt(int64(delay/2) + 1)
			rnd, err := crand.Int(crand.Reader, maxInt)
			var jitter time.Duration
			if err == nil {
				jitter = time.Duration(rnd.Int64()) - delay/4
			}
			wait = delay + jitter
			if wait < 0 {
				wait = delay
			}
		} else {
			wait = 0
		}
		// Wait respecting context cancellation
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
	}
	return resp, err
}

func isRetryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// rateLimitedRoundTripper gates requests through a rate limiter.
type rateLimitedRoundTripper struct {
	next http.RoundTripper
	lim  *rate.Limiter
}

func (r *rateLimitedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := r.lim.Wait(ctx); err != nil {
		return nil, err
	}
	return r.next.RoundTrip(req)
}

// Ping verifies the token works by hitting the /user endpoint.
func (c *Client) Ping(ctx context.Context) (*gitlab.User, *gitlab.Response, error) {
	return c.GL.Users.CurrentUser(gitlab.WithContext(ctx))
}

func defaultUserAgent() string {
	return "GoGatoZ/0.1 (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
}

// GraphQL executes a GraphQL query against the GitLab GraphQL endpoint and returns the raw data section.
// Endpoint: POST {baseURL}/api/graphql with JSON body {"query": "...", "variables": {..}}
// Authentication: sends both PRIVATE-TOKEN and Authorization: Bearer headers for broad compatibility.
func (c *Client) GraphQL(ctx context.Context, query string, variables map[string]any) (json.RawMessage, error) {
	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("nil client")
	}
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("empty GraphQL query")
	}
	u := c.baseURL + "/api/graphql"
	payload := map[string]any{"query": query}
	if variables != nil {
		payload["variables"] = variables
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL constructed from client's own baseURL
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graphql http %s", resp.Status)
	}
	var gr GraphQLResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&gr); err != nil {
		return nil, fmt.Errorf("decode graphql: %w", err)
	}
	if len(gr.Errors) > 0 {
		msg := gr.Errors[0].Message
		if strings.TrimSpace(msg) == "" {
			msg = "graphql error"
		}
		return nil, errors.New(msg)
	}
	return gr.Data, nil
}

// GetCIYMLTemplate fetches the content of a built-in GitLab CI template by name.
// It calls: GET /api/v4/templates/gitlab_ci_yml/:name and returns the YAML content.
func (c *Client) GetCIYMLTemplate(ctx context.Context, name string) (string, error) {
	if c == nil || c.httpClient == nil {
		return "", fmt.Errorf("nil client")
	}
	if name == "" {
		return "", fmt.Errorf("template name is required")
	}
	u := c.baseURL + "/api/v4/templates/gitlab_ci_yml/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL constructed from client's own baseURL
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("get template %s: %s", name, resp.Status)
	}
	var payload struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Content) == "" {
		return "", fmt.Errorf("empty template content: %s", name)
	}
	return payload.Content, nil
}

// GetProtectedBranches returns the list of protected branch names for a project.
// It paginates through all pages starting from the provided page (usually 0 or 1).
func (c *Client) GetProtectedBranches(ctx context.Context, projectID any, perPage int64, page int64) ([]string, error) {
	if c == nil || c.GL == nil {
		return nil, fmt.Errorf("nil gitlab client")
	}
	if perPage <= 0 {
		perPage = 100
	}
	if page <= 0 {
		page = 1
	}
	opt := &gitlab.ListProtectedBranchesOptions{ListOptions: gitlab.ListOptions{PerPage: perPage, Page: page}}
	var out []string
	for {
		list, resp, err := c.GL.ProtectedBranches.ListProtectedBranches(projectID, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		for _, b := range list {
			if b != nil && strings.TrimSpace(b.Name) != "" {
				out = append(out, b.Name)
			}
		}
		if resp == nil || resp.NextPage == 0 || resp.CurrentPage >= resp.TotalPages || len(list) == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return out, nil
}
