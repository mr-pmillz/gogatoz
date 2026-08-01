package artifactverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestVerifyFetchesBoundedSameOriginArtifact(t *testing.T) {
	t.Parallel()

	body := syntheticTarGzBytes(t, []syntheticArchiveFile{
		{path: "package/README.md", content: []byte("fixture\n")},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	report, err := Verify(context.Background(), Options{Artifact: server.URL + "/fixture.tgz", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Files != 1 || report.ArtifactType != "tar.gz" {
		t.Fatalf("HTTP artifact report = %+v", report)
	}
}

func TestVerifyRejectsCrossOriginRedirectEvenWithSuppliedClient(t *testing.T) {
	t.Parallel()

	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/artifact.tgz", http.StatusFound)
	}))
	defer source.Close()

	_, err := Verify(context.Background(), Options{Artifact: source.URL + "/redirect", HTTPClient: source.Client()})
	if err == nil || !strings.Contains(err.Error(), "changed origin") {
		t.Fatalf("Verify error = %v, want changed-origin rejection", err)
	}
	if destinationRequests.Load() != 0 {
		t.Fatalf("cross-origin destination received %d requests", destinationRequests.Load())
	}
}

func TestVerifyRejectsCredentialedAndOversizeURLs(t *testing.T) {
	t.Parallel()

	//nolint:gosec // Deliberately synthetic credentials verify that URL userinfo is rejected before any request.
	if _, err := Verify(context.Background(), Options{Artifact: "https://user:pass@registry.invalid/package.tgz"}); err == nil {
		t.Fatal("credentialed artifact URL returned nil error")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, err := Verify(context.Background(), Options{
		Artifact: server.URL + "/large.tgz", HTTPClient: server.Client(),
		Limits: Limits{MaxDownloadBytes: 10},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds 10 bytes") {
		t.Fatalf("oversize Verify error = %v", err)
	}
}
