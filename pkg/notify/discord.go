package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DiscordOptions configures the Discord webhook sender.
type DiscordOptions struct {
	WebhookURL string
	Timeout    time.Duration
	Client     *http.Client // optional; if nil, created with Timeout
}

// discordWebhookPayload is the JSON body sent to a Discord webhook.
type discordWebhookPayload struct {
	Content string         `json:"content,omitempty"`
	Embeds  []DiscordEmbed `json:"embeds,omitempty"`
}

// DiscordSender sends notifications via Discord webhooks.
type DiscordSender struct {
	url string
	hc  *http.Client
}

// NewDiscordSender creates a DiscordSender from options.
func NewDiscordSender(opts DiscordOptions) (*DiscordSender, error) {
	if opts.WebhookURL == "" {
		return nil, fmt.Errorf("notify: discord webhook URL is required")
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
	return &DiscordSender{url: opts.WebhookURL, hc: hc}, nil
}

// Send posts embeds to the Discord webhook. If the message contains more
// than 10 embeds, they are sent across multiple requests.
func (d *DiscordSender) Send(ctx context.Context, msg Message) error {
	embeds := msg.Embeds
	if len(embeds) == 0 && msg.Body != "" {
		// Fallback: send body as content if no embeds
		return d.post(ctx, discordWebhookPayload{Content: truncate(msg.Body, 2000)})
	}

	for i := 0; i < len(embeds); i += maxEmbedsPerMessage {
		end := min(i+maxEmbedsPerMessage, len(embeds))
		payload := discordWebhookPayload{Embeds: embeds[i:end]}
		if err := d.post(ctx, payload); err != nil {
			return err
		}
	}
	return nil
}

func (d *DiscordSender) post(ctx context.Context, payload discordWebhookPayload) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: discord encode: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("notify: discord request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := d.hc.Do(req) //nolint:gosec // G704: URL is user-configured webhook endpoint
	if err != nil {
		return fmt.Errorf("notify: discord: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: discord http %s", resp.Status)
	}
	return nil
}
