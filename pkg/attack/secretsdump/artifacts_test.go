package secretsdump

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// makeZip creates a ZIP archive in memory containing the given files (name -> content).
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestScrapeArtifacts_NoPipelines(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]any{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	findings, err := ScrapeArtifacts(context.Background(), cl, 1, "main", 3, 20, 16<<20, 256<<10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Fatalf("expected nil findings for no pipelines, got %d", len(findings))
	}
}

func TestScrapeArtifacts_Basic(t *testing.T) {
	zipData := makeZip(t, map[string]string{
		"env.txt": "API_KEY=secret123\nOTHER_VAR=value456\n",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": 10}})
	})
	mux.HandleFunc("/api/v4/projects/1/pipelines/10/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": 100, "name": "build"}})
	})
	mux.HandleFunc("/api/v4/projects/1/jobs/100/artifacts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(zipData)))
		w.Write(zipData) //nolint:errcheck
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	findings, err := ScrapeArtifacts(context.Background(), cl, 1, "main", 3, 20, 16<<20, 256<<10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings, got 0")
	}
	// Verify at least one finding has the expected key
	found := false
	for _, f := range findings {
		if f.Key == "API_KEY" && f.Value == "secret123" {
			found = true
			if f.JobID != 100 {
				t.Fatalf("expected JobID=100, got %d", f.JobID)
			}
			if f.JobName != "build" {
				t.Fatalf("expected JobName=build, got %s", f.JobName)
			}
			if f.File != "env.txt" {
				t.Fatalf("expected File=env.txt, got %s", f.File)
			}
		}
	}
	if !found {
		t.Fatalf("expected API_KEY=secret123 finding, findings=%+v", findings)
	}
}

func TestScrapeArtifacts_SkipsLargeFiles(t *testing.T) {
	// Create a zip with a large file entry that exceeds maxFileBytes
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Create a file header with a large uncompressed size
	header := &zip.FileHeader{
		Name:   "huge.txt",
		Method: zip.Store,
	}
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatalf("create header: %v", err)
	}
	// Write enough data to exceed a small maxFileBytes threshold
	bigContent := make([]byte, 1024)
	for i := range bigContent {
		bigContent[i] = 'A'
	}
	bigContent = append(bigContent, []byte("\nSECRET_KEY=should_not_appear\n")...)
	if _, err := w.Write(bigContent); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	zipData := buf.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": 10}})
	})
	mux.HandleFunc("/api/v4/projects/1/pipelines/10/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": 100, "name": "build"}})
	})
	mux.HandleFunc("/api/v4/projects/1/jobs/100/artifacts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData) //nolint:errcheck
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	// Set maxFileBytes very small so the file is skipped
	findings, err := ScrapeArtifacts(context.Background(), cl, 1, "main", 3, 20, 16<<20, 512)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have no findings because the file exceeds maxFileBytes
	for _, f := range findings {
		if f.Key == "SECRET_KEY" {
			t.Fatalf("expected SECRET_KEY to be skipped due to large file, but was found: %+v", f)
		}
	}
}

func TestScrapeArtifacts_SkipsNonTextExtensions(t *testing.T) {
	zipData := makeZip(t, map[string]string{
		"binary.exe": "SECRET=nope\n",
		"data.env":   "FOUND_KEY=found_val\n",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/pipelines", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": 10}})
	})
	mux.HandleFunc("/api/v4/projects/1/pipelines/10/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": 100, "name": "test"}})
	})
	mux.HandleFunc("/api/v4/projects/1/jobs/100/artifacts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData) //nolint:errcheck
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	findings, err := ScrapeArtifacts(context.Background(), cl, 1, "main", 3, 20, 16<<20, 256<<10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find FOUND_KEY from data.env but NOT SECRET from binary.exe
	for _, f := range findings {
		if f.Key == "SECRET" {
			t.Fatalf("expected .exe file to be skipped, but found SECRET")
		}
	}
	found := false
	for _, f := range findings {
		if f.Key == "FOUND_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected FOUND_KEY from .env file, findings=%+v", findings)
	}
}

func TestScrapeArtifacts_NilClient(t *testing.T) {
	_, err := ScrapeArtifacts(context.Background(), nil, 1, "main", 3, 20, 16<<20, 256<<10)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}
