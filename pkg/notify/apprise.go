package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const defaultAppriseTag = "gogatoz"

// AppriseOptions configures the Apprise notification sender.
type AppriseOptions struct {
	URL     string        // full Apprise API URL (e.g., https://apprise.example/notify/apprise)
	Tag     string        // routing tag (default: "gogatoz")
	Timeout time.Duration // HTTP request timeout
	Client  *http.Client  // optional; if nil, created with Timeout
}

// ApprisePayload is the JSON body sent to the Apprise API.
type ApprisePayload struct {
	Body   string `json:"body"`
	Title  string `json:"title"`
	Type   string `json:"type"`   // info, success, warning, failure
	Format string `json:"format"` // text, markdown, html
	Tag    string `json:"tag"`
}

// AppriseSender sends notifications via the Apprise API.
type AppriseSender struct {
	url string
	tag string
	hc  *http.Client
}

// NewAppriseSender creates an AppriseSender from options.
func NewAppriseSender(opts AppriseOptions) (*AppriseSender, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("notify: apprise URL is required")
	}
	tag := opts.Tag
	if tag == "" {
		tag = defaultAppriseTag
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
	return &AppriseSender{url: opts.URL, tag: tag, hc: hc}, nil
}

// Send posts a Message to the Apprise API as markdown.
func (a *AppriseSender) Send(ctx context.Context, msg Message) error {
	typ := msg.Type
	if typ == "" {
		typ = TypeInfo
	}

	payload := ApprisePayload{
		Body:   msg.Body,
		Title:  msg.Title,
		Type:   typ,
		Format: "markdown",
		Tag:    a.tag,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: apprise encode: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("notify: apprise request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := a.hc.Do(req) //nolint:gosec // G704: URL is user-configured webhook endpoint
	if err != nil {
		return fmt.Errorf("notify: apprise: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: apprise http %s", resp.Status)
	}
	return nil
}
