package gitlabx

import (
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
		Body:       io.NopCloser(strings.NewReader("")),
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
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After 2 attempts, return last response even if retryable
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after giving up, got %d", resp.StatusCode)
	}
	if frt.idx != 2 {
		t.Fatalf("expected 2 attempts, got %d", frt.idx)
	}
}
