package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

// Options configures the Notifier.
// URL is required. Timeout applies to the HTTP client if a custom Client isn't provided.
// Additional headers can be supplied via Headers; Content-Type: application/json is always set.
type Options struct {
	URL     string
	Headers map[string]string
	Timeout time.Duration
	Client  *http.Client // optional, if nil an internal client is used
}

// Notifier posts JSON payloads to a webhook (e.g., for notifications/evidence shipping).
// It is intentionally small and does not manage batching or retries; callers can wrap it.
type Notifier struct {
	url     string
	headers map[string]string
	hc      *http.Client
}

// New creates a Notifier from Options.
func New(opts Options) (*Notifier, error) {
	u := opts.URL
	if u == "" {
		return nil, fmt.Errorf("notify: URL is required")
	}
	var hc *http.Client
	if opts.Client != nil {
		hc = opts.Client
	} else {
		t := opts.Timeout
		if t == 0 {
			t = 30 * time.Second
		}
		hc = &http.Client{Timeout: t}
	}
	// Copy headers map to avoid external mutation
	h := map[string]string{}
	maps.Copy(h, opts.Headers)
	return &Notifier{url: u, headers: h, hc: hc}, nil
}

// SendJSON posts payload as JSON to the configured webhook URL.
func (n *Notifier) SendJSON(ctx context.Context, payload any) error {
	if n == nil || n.hc == nil {
		return fmt.Errorf("notify: nil client")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	for k, v := range n.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := n.hc.Do(req) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: http %s", resp.Status)
	}
	return nil
}

// FindingEnvelope is a simple schema to wrap analysis findings for notifications.
// It can be extended later to match configuration/notifications.json taxonomy.
type FindingEnvelope struct {
	Project  string            `json:"project,omitempty"`
	Finding  analyze.Finding   `json:"finding"`
	Tool     string            `json:"tool"`
	Version  string            `json:"version,omitempty"`
	Occurred time.Time         `json:"occurred_at"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// SendFinding wraps a single analyze.Finding with basic metadata and sends it.
func (n *Notifier) SendFinding(ctx context.Context, project string, f analyze.Finding, meta map[string]string) error {
	env := FindingEnvelope{
		Project:  project,
		Finding:  f,
		Tool:     "GoGatoZ",
		Occurred: time.Now().UTC(),
		Meta:     meta,
	}
	return n.SendJSON(ctx, env)
}
