package gitlabx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeRT struct {
	codes []int
	idx   int
}

func (f *fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	code := http.StatusOK
	if f.idx < len(f.codes) {
		code = f.codes[f.idx]
	}
	f.idx++
	resp := &http.Response{
		StatusCode: code,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(http.StatusText(code))),
	}
	// Set Retry-After=0 to avoid sleep if retry occurs
	resp.Header.Set("Retry-After", "0")
	return resp, nil
}

func TestRetryingRoundTripper_RetriesOn429ThenSucceeds(t *testing.T) {
	frt := &fakeRT{codes: []int{http.StatusTooManyRequests, http.StatusOK}}
	rt := &retryingRoundTripper{next: frt, maxAttempts: 3, baseDelay: 10 * time.Millisecond, maxDelay: 20 * time.Millisecond}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid", nil)
	resp, err := rt.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if frt.idx != 2 {
		t.Fatalf("expected 2 attempts, got %d", frt.idx)
	}
}

func TestRetryingRoundTripper_GivesUpAfterMaxAttempts(t *testing.T) {
	frt := &fakeRT{codes: []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests}}
	rt := &retryingRoundTripper{next: frt, maxAttempts: 2, baseDelay: 1 * time.Millisecond, maxDelay: 1 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.invalid", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After 2 attempts, return last response even if retryable.
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after giving up, got %d", resp.StatusCode)
	}
	if frt.idx != 2 {
		t.Fatalf("expected 2 attempts, got %d", frt.idx)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil || string(body) != http.StatusText(http.StatusTooManyRequests) {
		t.Fatalf("final response body was not readable: body=%q err=%v", body, readErr)
	}
}

func TestRetryingRoundTripper_DoesNotRetryUnsafeMutation(t *testing.T) {
	frt := &fakeRT{codes: []int{http.StatusServiceUnavailable, http.StatusOK}}
	rt := &retryingRoundTripper{next: frt, maxAttempts: 3, baseDelay: time.Millisecond}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.invalid", strings.NewReader("mutation"))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if frt.idx != 1 || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unsafe POST was retried: attempts=%d status=%d", frt.idx, resp.StatusCode)
	}
}

type bodyRecordingRT struct {
	bodies []string
	calls  int
}

func (r *bodyRecordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	r.bodies = append(r.bodies, string(b))
	r.calls++
	code := http.StatusServiceUnavailable
	if r.calls == 2 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Retry-After": []string{"0"}},
		Body:       io.NopCloser(bytes.NewBufferString("response")),
	}, nil
}

func TestRetryingRoundTripper_RewindsReplayableBody(t *testing.T) {
	frt := &bodyRecordingRT{}
	rt := &retryingRoundTripper{next: frt, maxAttempts: 2, baseDelay: time.Millisecond}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "http://example.invalid", strings.NewReader("same-body"))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if len(frt.bodies) != 2 || frt.bodies[0] != "same-body" || frt.bodies[1] != "same-body" {
		t.Fatalf("request body was not replayed exactly: %v", frt.bodies)
	}
}

func TestNew_RejectsInvalidRateLimit(t *testing.T) {
	if _, err := New("https://gitlab.example", "token", WithRateLimit(0, 1)); err == nil {
		t.Fatal("expected zero requests per second to be rejected")
	}
	if _, err := New("https://gitlab.example", "token", WithRateLimit(1, 0)); err == nil {
		t.Fatal("expected zero burst to be rejected")
	}
}
