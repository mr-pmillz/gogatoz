package tamper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestPublishPackage_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/packages/generic/") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":         1,
				"package_id": 10,
				"file_name":  "payload.tar.gz",
				"size":       1024,
				"file":       map[string]string{"url": "https://gitlab.local/file"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}

	result, err := PublishPackage(context.Background(), client, 42, "my-pkg", "1.0.0", "payload.tar.gz", strings.NewReader("malicious content"))
	if err != nil {
		t.Fatal(err)
	}
	if result.PackageName != "my-pkg" {
		t.Errorf("expected package name my-pkg, got %s", result.PackageName)
	}
	if result.PackageVersion != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", result.PackageVersion)
	}
	if result.FileName != "payload.tar.gz" {
		t.Errorf("expected file name payload.tar.gz, got %s", result.FileName)
	}
}

func TestPublishPackage_MissingFields(t *testing.T) {
	client, _ := gitlabx.New("http://localhost", "tok")
	_, err := PublishPackage(context.Background(), client, 1, "", "1.0", "f.tar", nil)
	if err == nil {
		t.Fatal("expected error for empty package name")
	}
	_, err = PublishPackage(context.Background(), client, 1, "pkg", "", "f.tar", nil)
	if err == nil {
		t.Fatal("expected error for empty version")
	}
	_, err = PublishPackage(context.Background(), client, 1, "pkg", "1.0", "", nil)
	if err == nil {
		t.Fatal("expected error for empty file name")
	}
}
