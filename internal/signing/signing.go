// SPDX-License-Identifier: Apache-2.0

// Package signing handles RSA keypair lifecycle and profile property signing for the Yggdrasil protocol.
package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// defaultKeyBits is the RSA key size used in production.
// Mojang uses 4096-bit keys; authlib-injector clients expect a key of this strength.
const defaultKeyBits = 4096

// KeyManager holds an RSA private key and exposes signing and public-key-export operations.
// It is the sole owner of the private key material; nothing outside this package reads it.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicPEM  string
}

// New loads an RSA private key from keyPath. If the file does not exist it generates
// a fresh 4096-bit RSA key, persists it to keyPath as a PKCS#8 PEM file with mode
// 0600, and uses it. Parent directories are created automatically.
func New(keyPath string) (*KeyManager, error) {
	return newWithBits(keyPath, defaultKeyBits)
}

// newWithBits is the internal constructor that accepts a custom key bit size.
// Tests pass a smaller value (typically 2048) to keep key generation fast while
// still exercising the full code path. Production code always calls New, which
// forwards defaultKeyBits (4096).
func newWithBits(keyPath string, bits int) (*KeyManager, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading key file %s: %w", keyPath, err)
	}

	var privateKey *rsa.PrivateKey
	if os.IsNotExist(err) {
		slog.Info("RSA signing key not found, generating a new one", "path", keyPath, "bits", bits)
		privateKey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("generating RSA key: %w", err)
		}
		if err := persistKey(keyPath, privateKey); err != nil {
			return nil, err
		}
		slog.Info("RSA signing key persisted", "path", keyPath)
	} else {
		privateKey, err = loadKey(data)
		if err != nil {
			return nil, fmt.Errorf("loading RSA key from %s: %w", keyPath, err)
		}
		slog.Info("RSA signing key loaded", "path", keyPath, "bits", privateKey.N.BitLen())
	}

	pubPEM, err := marshalPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}

	return &KeyManager{
		privateKey: privateKey,
		publicPEM:  pubPEM,
	}, nil
}

// SignSHA1 returns the raw RSASSA-PKCS1-v1_5 signature over a SHA-1 digest of data.
// SHA-1 is mandatory here for authlib-injector / Minecraft compatibility (see SignProperty).
func (km *KeyManager) SignSHA1(data []byte) ([]byte, error) {
	digest := sha1.Sum(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, km.privateKey, crypto.SHA1, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}
	return sig, nil
}

// SignProperty returns the base64-standard-encoded SHA1withRSA signature of value.
//
// The algorithm is RSASSA-PKCS1-v1_5 over a SHA-1 digest. SHA-1 is intentional and
// mandatory here: the Yggdrasil/authlib-injector specification requires exactly this
// algorithm for texture property signatures, because Minecraft clients verify against
// SHA1withRSA. Replacing SHA-1 with a stronger hash (e.g. SHA-256) would silently
// break signature verification in every launcher and server using authlib-injector.
func (km *KeyManager) SignProperty(value string) (string, error) {
	sig, err := km.SignSHA1([]byte(value))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// PublicKeyPEM returns the PKIX/PEM-encoded public key (PEM type "PUBLIC KEY").
// The authlib-injector metadata document serves this value as signaturePublickey.
func (km *KeyManager) PublicKeyPEM() string {
	return km.publicPEM
}

// PublicKey returns the RSA public key. It is exported for use in tests and in
// handlers that need to expose the key material (e.g. the metadata document builder).
func (km *KeyManager) PublicKey() *rsa.PublicKey {
	return &km.privateKey.PublicKey
}

// persistKey serialises key as a PKCS#8 PEM file and writes it to keyPath with
// mode 0600. Parent directories are created with mode 0700 if absent.
func persistKey(keyPath string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key to PKCS#8: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("creating parent directory for %s: %w", keyPath, err)
	}
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		return fmt.Errorf("writing key file %s: %w", keyPath, err)
	}
	return nil
}

// loadKey parses a PEM-encoded PKCS#8 RSA private key from data.
func loadKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#8 private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key (got %T)", key)
	}
	return rsaKey, nil
}

// marshalPublicKeyPEM encodes pub as a PKIX PEM block ("BEGIN PUBLIC KEY").
func marshalPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key to PKIX: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
