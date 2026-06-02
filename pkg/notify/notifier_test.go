package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

func TestNotifier_SendJSON_SuccessAndHeaders(t *testing.T) {
	var seenCT, seenX string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCT = r.Header.Get("Content-Type")
		seenX = r.Header.Get("X-Token")
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Body.Close error: %v", err)
			}
		}(r.Body)
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := New(Options{URL: srv.URL, Headers: map[string]string{"X-Token": "abc"}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("new notifier: %v", err)
	}
	payload := map[string]any{"ok": true}
	if err := n.SendJSON(context.Background(), payload); err != nil {
		t.Fatalf("SendJSON error: %v", err)
	}
	if seenCT != contentTypeJSON {
		t.Fatalf("expected Content-Type application/json, got %q", seenCT)
	}
	if seenX != "abc" {
		t.Fatalf("expected header X-Token=abc, got %q", seenX)
	}
	if v, _ := got["ok"].(bool); !v {
		t.Fatalf("expected ok=true in payload, got %v", got)
	}
}

func TestNotifier_SendJSON_HTTPSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	n, err := New(Options{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = n.SendJSON(context.Background(), map[string]any{"x": 1})
	if err == nil || !strings.Contains(err.Error(), "http 400") {
		t.Fatalf("expected http error surfaced, got %v", err)
	}
}

func TestNotifier_SendJSON_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n, err := New(Options{URL: srv.URL, Timeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	err = n.SendJSON(context.Background(), map[string]any{"x": 1})
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
}

func TestNotifier_SendFinding_WrapsFinding(t *testing.T) {
	var env FindingEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Body.Close error: %v", err)
			}
		}(r.Body)
		_ = json.NewDecoder(r.Body).Decode(&env)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n, err := New(Options{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f := analyze.Finding{ID: "TEST", Severity: analyze.SeverityHigh, Title: "t"}
	if err := n.SendFinding(context.Background(), "group/proj", f, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("SendFinding error: %v", err)
	}
	if env.Tool != "GoGatoZ" || env.Project != "group/proj" || env.Finding.ID != "TEST" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}
