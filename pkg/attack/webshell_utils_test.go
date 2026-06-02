package attack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestISOTimeNow(t *testing.T) {
	got := ISOTimeNow()
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("not RFC3339: %v (%q)", err, got)
	}
	// ensure no sub-second precision
	tt, _ := time.Parse(time.RFC3339, got)
	if tt.Nanosecond() != 0 {
		t.Fatalf("expected zero sub-second, got %d", tt.Nanosecond())
	}
}

func TestPollWithTimeout_SuccessAndTimeout(t *testing.T) {
	ctx := context.Background()
	// success path
	start := time.Now()
	err := PollWithTimeout(ctx, 10*time.Millisecond, 200*time.Millisecond, func(context.Context) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("expected fast return")
	}
	// timeout path
	err = PollWithTimeout(ctx, 10*time.Millisecond, 100*time.Millisecond, func(context.Context) (bool, error) { return false, nil })
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestWaitForPipelineForRef(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/123/pipelines", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if calls < 3 {
			json.NewEncoder(w).Encode([]struct {
				ID int64 `json:"id"`
			}{})
			return
		}
		json.NewEncoder(w).Encode([]struct {
			ID int64 `json:"id"`
		}{{ID: 42}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cl, err := gitlabx.New(srv.URL, "")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()
	id, err := WaitForPipelineForRef(ctx, cl, 123, "", 20*time.Millisecond, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if id != 42 {
		t.Fatalf("expected pipeline id 42, got %d", id)
	}
}
