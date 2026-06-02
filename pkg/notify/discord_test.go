package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestDiscordSender_Send(t *testing.T) {
	var received discordWebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != contentTypeJSON {
			t.Errorf("expected application/json, got %s", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender, err := NewDiscordSender(DiscordOptions{WebhookURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	msg := Message{
		Embeds: []DiscordEmbed{
			{Title: "Test", Description: "desc", Color: ColorHigh},
		},
	}
	if err := sender.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	if len(received.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(received.Embeds))
	}
	if received.Embeds[0].Title != "Test" {
		t.Errorf("embed title = %q, want Test", received.Embeds[0].Title)
	}
	if received.Embeds[0].Color != ColorHigh {
		t.Errorf("embed color = %d, want %d", received.Embeds[0].Color, ColorHigh)
	}
}

func TestDiscordSender_Chunking(t *testing.T) {
	var mu sync.Mutex
	var calls int
	var allEmbeds [][]DiscordEmbed

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p discordWebhookPayload
		_ = json.Unmarshal(body, &p)
		mu.Lock()
		calls++
		allEmbeds = append(allEmbeds, p.Embeds)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender, _ := NewDiscordSender(DiscordOptions{WebhookURL: srv.URL})

	// 12 embeds → 2 requests (10 + 2)
	var embeds []DiscordEmbed
	for range 12 {
		embeds = append(embeds, DiscordEmbed{Title: "E", Color: ColorLow})
	}
	if err := sender.Send(context.Background(), Message{Embeds: embeds}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected 2 requests, got %d", calls)
	}
	if len(allEmbeds[0]) != 10 {
		t.Errorf("first batch = %d, want 10", len(allEmbeds[0]))
	}
	if len(allEmbeds[1]) != 2 {
		t.Errorf("second batch = %d, want 2", len(allEmbeds[1]))
	}
}

func TestDiscordSender_FallbackContent(t *testing.T) {
	var received discordWebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender, _ := NewDiscordSender(DiscordOptions{WebhookURL: srv.URL})
	// No embeds, just body text
	if err := sender.Send(context.Background(), Message{Body: "hello"}); err != nil {
		t.Fatal(err)
	}

	if received.Content != "hello" {
		t.Errorf("content = %q, want hello", received.Content)
	}
}

func TestDiscordSender_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	sender, _ := NewDiscordSender(DiscordOptions{WebhookURL: srv.URL})
	err := sender.Send(context.Background(), Message{
		Embeds: []DiscordEmbed{{Title: "X"}},
	})
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !contains(err.Error(), "discord http 403") {
		t.Errorf("error = %q, want containing discord http 403", err.Error())
	}
}

func TestDiscordSender_MissingURL(t *testing.T) {
	_, err := NewDiscordSender(DiscordOptions{})
	if err == nil {
		t.Fatal("expected error on missing URL")
	}
}
