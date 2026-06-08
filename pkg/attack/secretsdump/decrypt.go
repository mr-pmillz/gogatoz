package secretsdump

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// DecryptOpenSSLAES decrypts data produced by:
//
//	openssl enc -aes-256-cbc -pbkdf2 -pass pass:$key
//
// Format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext.
// Key derivation: PBKDF2 with SHA256, 10000 iterations (OpenSSL 3.x default).
func DecryptOpenSSLAES(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short")
	}
	if string(data[:8]) != "Salted__" {
		return nil, fmt.Errorf("missing Salted__ header")
	}
	salt := data[8:16]
	ciphertext := data[16:]

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

	return pkcs7Unpad(plaintext)
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

// DecryptRSAPKCS1v15 decrypts encData using a PEM-encoded RSA private key (PKCS1v15).
// Supports both PKCS#1 and PKCS#8 PEM formats.
func DecryptRSAPKCS1v15(privKeyPEM, encData []byte) ([]byte, error) {
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	var privKey *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privKey = k
	} else if k8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privKey, ok = k8.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
	} else {
		return nil, fmt.Errorf("parse RSA private key: unsupported PEM type %q", block.Type)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privKey, encData) //nolint:staticcheck
}

// DecryptExfilArtifacts decrypts artifact-based exfil files.
// privKeyPEM is the RSA private key PEM; secretsEnc is the raw bytes of secrets.enc
// (AES-256-CBC encrypted); aesEnc is the raw bytes of aes.enc (RSA-encrypted AES passphrase).
// Returns the plaintext secrets as a key/value map.
func DecryptExfilArtifacts(privKeyPEM, secretsEnc, aesEnc []byte) (map[string]string, error) {
	passphrase, err := DecryptRSAPKCS1v15(privKeyPEM, aesEnc)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt aes key: %w", err)
	}
	plaintext, err := DecryptOpenSSLAES(secretsEnc, string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("aes decrypt secrets: %w", err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("unmarshal secrets: %w", err)
	}
	return secrets, nil
}
