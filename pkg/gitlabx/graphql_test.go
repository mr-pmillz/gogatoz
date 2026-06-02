package gitlabx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "t0k3n"

func TestGraphQL_SendsHeadersAndParsesData(t *testing.T) {
	// Fake server to capture request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/graphql" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("PRIVATE-TOKEN"); got != testToken {
			t.Fatalf("missing PRIVATE-TOKEN header, got %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Fatalf("missing Authorization header, got %q", got)
		}
		// echo a minimal GraphQL response
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": {"ok": true}}`))
	}))
	defer srv.Close()

	cl, err := New(srv.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	data, err := cl.GraphQL(context.Background(), "query { currentUser { username } }", map[string]any{"x": 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid data json: %v", err)
	}
	if v, _ := m["ok"].(bool); !v {
		t.Fatalf("expected ok=true in data: %v", m)
	}
}

func TestGraphQL_PropagatesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors": [{"message": "boom"}]}`))
	}))
	defer srv.Close()
	cl, err := New(srv.URL, "t0k3n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.GraphQL(context.Background(), "query { bad }", nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected boom error, got %v", err)
	}
}
