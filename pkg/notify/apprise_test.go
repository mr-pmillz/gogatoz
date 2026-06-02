package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAppriseSender_Send(t *testing.T) {
	var received ApprisePayload
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
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, err := NewAppriseSender(AppriseOptions{URL: srv.URL, Tag: defaultAppriseTag})
	if err != nil {
		t.Fatal(err)
	}

	msg := Message{
		Title: "Test Title",
		Body:  "## Test Body\n\nSome **markdown**",
		Type:  TypeWarning,
	}
	if err := sender.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	if received.Title != "Test Title" {
		t.Errorf("title = %q, want Test Title", received.Title)
	}
	if received.Body != "## Test Body\n\nSome **markdown**" {
		t.Errorf("body = %q", received.Body)
	}
	if received.Type != TypeWarning {
		t.Errorf("type = %q, want warning", received.Type)
	}
	if received.Format != "markdown" {
		t.Errorf("format = %q, want markdown", received.Format)
	}
	if received.Tag != defaultAppriseTag {
		t.Errorf("tag = %q, want gogatoz", received.Tag)
	}
}

func TestAppriseSender_DefaultTag(t *testing.T) {
	var received ApprisePayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, err := NewAppriseSender(AppriseOptions{URL: srv.URL}) // no tag
	if err != nil {
		t.Fatal(err)
	}
	_ = sender.Send(context.Background(), Message{Title: "t", Body: "b"})

	if received.Tag != defaultAppriseTag {
		t.Errorf("default tag = %q, want gogatoz", received.Tag)
	}
}

func TestAppriseSender_CustomTag(t *testing.T) {
	var received ApprisePayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, err := NewAppriseSender(AppriseOptions{URL: srv.URL, Tag: "custom-tag"})
	if err != nil {
		t.Fatal(err)
	}
	_ = sender.Send(context.Background(), Message{Title: "t", Body: "b"})

	if received.Tag != "custom-tag" {
		t.Errorf("tag = %q, want custom-tag", received.Tag)
	}
}

func TestAppriseSender_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sender, err := NewAppriseSender(AppriseOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(context.Background(), Message{Body: "test"})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if want := "apprise http 400"; !containsStr(err.Error(), want) {
		t.Errorf("error = %q, want containing %q", err.Error(), want)
	}
}

func TestAppriseSender_MissingURL(t *testing.T) {
	_, err := NewAppriseSender(AppriseOptions{})
	if err == nil {
		t.Fatal("expected error on missing URL")
	}
}

func TestAppriseSender_DefaultType(t *testing.T) {
	var received ApprisePayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, _ := NewAppriseSender(AppriseOptions{URL: srv.URL})
	_ = sender.Send(context.Background(), Message{Body: "b"}) // no Type set

	if received.Type != TypeInfo {
		t.Errorf("default type = %q, want info", received.Type)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && contains(s, sub))
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
