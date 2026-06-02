package gitlabx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetProjectLanguages_SuccessAndHeaders(t *testing.T) {
	var seenPath, seenToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenToken = r.Header.Get("PRIVATE-TOKEN")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]float64{"Go": 95.5, "Makefile": 1.0})
	}))
	defer srv.Close()
	cl, err := New(srv.URL, "t0k3n")
	if err != nil {
		t.Fatal(err)
	}
	langs, err := cl.GetProjectLanguages(context.Background(), 123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenPath != "/api/v4/projects/123/languages" {
		t.Fatalf("unexpected path: %s", seenPath)
	}
	if seenToken != "t0k3n" {
		t.Fatalf("expected PRIVATE-TOKEN header set, got %q", seenToken)
	}
	if _, ok := langs["Go"]; !ok {
		t.Fatalf("expected Go in languages: %v", langs)
	}
}

func TestGetProjectLanguages_HTTPSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer srv.Close()
	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.GetProjectLanguages(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "http 400") {
		t.Fatalf("expected http error, got %v", err)
	}
}
