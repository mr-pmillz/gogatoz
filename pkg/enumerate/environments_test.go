package enumerate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestFetchEnvironments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/1/environments" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "20")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "2")
			envs := []map[string]any{
				{"id": 1, "name": "production", "tier": "production", "state": "available", "external_url": "https://prod.example.com"},
				{"id": 2, "name": "staging", "tier": "staging", "state": "available"},
			}
			json.NewEncoder(w).Encode(envs)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	envs, err := FetchEnvironments(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("FetchEnvironments: %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 envs, got %d", len(envs))
	}
	if envs[0].Name != "production" || envs[0].Tier != "production" {
		t.Errorf("env[0] mismatch: %+v", envs[0])
	}
}

func TestFetchEnvironments_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "20")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "0")
		json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer srv.Close()

	cl, _ := gitlabx.New(srv.URL, "tok")
	envs, err := FetchEnvironments(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(envs) != 0 {
		t.Errorf("expected 0 envs, got %d", len(envs))
	}
}
