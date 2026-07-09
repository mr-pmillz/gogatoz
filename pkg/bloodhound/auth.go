package bloodhound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// Authenticator signs an outgoing HTTP request for the BloodHound CE API.
type Authenticator interface {
	Authenticate(req *http.Request, body []byte) error
}

// HMACAuth implements BloodHound's chained HMAC-SHA256 request signing:
//  1. OperationKey = HMAC-SHA256(tokenKey, method + uri)
//  2. DateKey      = HMAC-SHA256(OperationKey, datetimeToHour)
//  3. Signature    = HMAC-SHA256(DateKey, requestBody)
type HMACAuth struct {
	TokenID  string
	TokenKey string
	NowFunc  func() time.Time // for testing
}

// Authenticate signs req using the BloodHound CE chained HMAC-SHA256 scheme.
func (h *HMACAuth) Authenticate(req *http.Request, body []byte) error {
	if h.TokenID == "" || h.TokenKey == "" {
		return fmt.Errorf("HMAC auth requires both token-id and token-key")
	}

	now := time.Now
	if h.NowFunc != nil {
		now = h.NowFunc
	}
	t := now().UTC()

	uri := req.URL.RequestURI()

	opMAC := hmac.New(sha256.New, []byte(h.TokenKey))
	opMAC.Write([]byte(req.Method + uri))
	opKey := opMAC.Sum(nil)

	dateMAC := hmac.New(sha256.New, opKey)
	dateMAC.Write([]byte(t.Format("2006-01-02T15")))
	dateKey := dateMAC.Sum(nil)

	sigMAC := hmac.New(sha256.New, dateKey)
	if body != nil {
		sigMAC.Write(body)
	}
	sig := base64.StdEncoding.EncodeToString(sigMAC.Sum(nil))

	req.Header.Set("Authorization", fmt.Sprintf("bhesignature %s", h.TokenID))
	req.Header.Set("RequestDate", t.Format(time.RFC3339))
	req.Header.Set("Signature", sig)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return nil
}

// BearerAuth implements simple JWT Bearer token authentication.
type BearerAuth struct {
	Token string
}

// Authenticate sets the Authorization header with a Bearer token.
func (b *BearerAuth) Authenticate(req *http.Request, _ []byte) error {
	if b.Token == "" {
		return fmt.Errorf("bearer auth requires a non-empty token")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", b.Token))
	return nil
}
