package bloodhound

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHMACAuth(t *testing.T) {
	fixedTime := time.Date(2025, 7, 1, 14, 30, 0, 0, time.UTC)
	auth := &HMACAuth{
		TokenID:  "test-token-id",
		TokenKey: "test-secret-key",
		NowFunc:  func() time.Time { return fixedTime },
	}

	req, _ := http.NewRequest(http.MethodPost, "https://bh.example.com/api/v2/file-upload/start", nil)
	body := []byte("{}")

	if err := auth.Authenticate(req, body); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "bhesignature ") {
		t.Errorf("Authorization header = %q, want prefix 'bhesignature '", authHeader)
	}
	if !strings.Contains(authHeader, "test-token-id") {
		t.Error("Authorization header missing token ID")
	}

	sig := req.Header.Get("Signature")
	if sig == "" {
		t.Error("Signature header is empty")
	}

	dateHdr := req.Header.Get("RequestDate")
	if dateHdr == "" {
		t.Error("RequestDate header is empty")
	}
	if !strings.HasPrefix(dateHdr, "2025-07-01T14:") {
		t.Errorf("RequestDate = %q, expected to start with 2025-07-01T14:", dateHdr)
	}
}

func TestHMACAuthDeterministic(t *testing.T) {
	fixedTime := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	auth := &HMACAuth{
		TokenID:  "id",
		TokenKey: "key",
		NowFunc:  func() time.Time { return fixedTime },
	}

	req1, _ := http.NewRequest(http.MethodGet, "https://bh.example.com/api/v2/extensions", nil)
	req2, _ := http.NewRequest(http.MethodGet, "https://bh.example.com/api/v2/extensions", nil)

	if err := auth.Authenticate(req1, nil); err != nil {
		t.Fatal(err)
	}
	if err := auth.Authenticate(req2, nil); err != nil {
		t.Fatal(err)
	}

	if req1.Header.Get("Signature") != req2.Header.Get("Signature") {
		t.Error("same request at same time should produce same signature")
	}
}

func TestHMACAuthMissingCredentials(t *testing.T) {
	auth := &HMACAuth{TokenID: "", TokenKey: ""}
	req, _ := http.NewRequest(http.MethodGet, "https://bh.example.com/api/v2/extensions", nil)
	if err := auth.Authenticate(req, nil); err == nil {
		t.Error("expected error for empty credentials")
	}
}

func TestBearerAuth(t *testing.T) {
	auth := &BearerAuth{Token: "jwt-token-here"} //nolint:gosec // test value
	req, _ := http.NewRequest(http.MethodGet, "https://bh.example.com/api/v2/extensions", nil)
	if err := auth.Authenticate(req, nil); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer jwt-token-here" {
		t.Errorf("Authorization = %q, want 'Bearer jwt-token-here'", got)
	}
}

func TestBearerAuthEmpty(t *testing.T) {
	auth := &BearerAuth{Token: ""}
	req, _ := http.NewRequest(http.MethodGet, "https://bh.example.com/api/v2/extensions", nil)
	if err := auth.Authenticate(req, nil); err == nil {
		t.Error("expected error for empty token")
	}
}
