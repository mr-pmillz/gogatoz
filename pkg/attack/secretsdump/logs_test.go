package secretsdump

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

type pipelinesResp struct {
	ID int `json:"id"`
}

type job struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func TestScrapeJobLogs_Basic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/123/pipelines", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]pipelinesResp{{ID: 1}})
	})
	mux.HandleFunc("/api/v4/projects/123/pipelines/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]job{{ID: 10, Name: "build"}, {ID: 11, Name: "test"}})
	})
	mux.HandleFunc("/api/v4/projects/123/jobs/10/trace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("HELLO=world\n" + RedactionKeyMasked + "=true\n" + RedactionKeyJobToken + "=abc\n"))
	})
	mux.HandleFunc("/api/v4/projects/123/jobs/11/trace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("API_KEY=secret123\nNOTENV something\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	finds, err := ScrapeJobLogs(context.Background(), cl, 123, "", 2, 10)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	if len(finds) == 0 {
		t.Fatalf("expected findings, got 0")
	}
	// ensure we don't include masked and CI tokens
	for _, f := range finds {
		if f.Key == RedactionKeyMasked || f.Key == RedactionKeyJobToken {
			t.Fatalf("unexpected key included: %s", f.Key)
		}
	}
}
