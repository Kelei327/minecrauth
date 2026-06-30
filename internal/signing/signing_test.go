package signing

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"path/filepath"
	"testing"
)

// testKeyBits is smaller than the 4096-bit production default so that RSA key
// generation in tests completes in well under a second without sacrificing
// coverage of the generation, persistence, and signing code paths.
const testKeyBits = 2048

// newTestManager creates a KeyManager backed by a temporary directory.
func newTestManager(t *testing.T) *KeyManager {
	t.Helper()
	km, err := newWithBits(filepath.Join(t.TempDir(), "signing.key"), testKeyBits)
	if err != nil {
		t.Fatalf("newWithBits: %v", err)
	}
	return km
}

// TestSignPropertyRoundTrip signs a realistic Yggdrasil texture property value and
// independently verifies the signature using rsa.VerifyPKCS1v15 with crypto.SHA1.
// The test fails if the algorithm or hash are wrong, acting as a canary for the
// SHA1withRSA contract required by authlib-injector clients.
func TestSignPropertyRoundTrip(t *testing.T) {
	km := newTestManager(t)

	// Canary value: a realistic textures property blob as sent in the Yggdrasil profile.
	value := `{"timestamp":1700000000000,"profileId":"6d4f8c8a3b1e4f2d9a0e7c5b3f1d8a2e","profileName":"SteveMine","textures":{"SKIN":{"url":"http://textures.example.com/texture/abc123def456"}}}`

	sig64, err := km.SignProperty(value)
	if err != nil {
		t.Fatalf("SignProperty: %v", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil {
		t.Fatalf("base64 decode signature: %v", err)
	}

	// Independent verification: recompute the SHA-1 digest and call VerifyPKCS1v15
	// directly. This would fail if SignProperty used a different hash or padding.
	digest := sha1.Sum([]byte(value))
	if err := rsa.VerifyPKCS1v15(km.PublicKey(), crypto.SHA1, digest[:], sigBytes); err != nil {
		t.Fatalf("signature verification failed (expected SHA1withRSA/PKCS1v15): %v", err)
	}
}

// TestSignPropertyTamper verifies that flipping one byte of the signed value causes
// independent verification to fail, confirming the signature is bound to the exact content.
func TestSignPropertyTamper(t *testing.T) {
	km := newTestManager(t)
	value := "textures-property-canary-value"

	sig64, err := km.SignProperty(value)
	if err != nil {
		t.Fatalf("SignProperty: %v", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil {
		t.Fatalf("base64 decode signature: %v", err)
	}

	// Flip the first byte to simulate content tampering.
	tampered := []byte(value)
	tampered[0] ^= 0xFF
	digest := sha1.Sum(tampered)

	if err := rsa.VerifyPKCS1v15(km.PublicKey(), crypto.SHA1, digest[:], sigBytes); err == nil {
		t.Fatal("verification succeeded for a tampered value; signature must not be valid after content modification")
	}
}

// TestKeyPersistence confirms that calling newWithBits twice on the same path returns
// the same key (equal modulus N) rather than regenerating it.
func TestKeyPersistence(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signing.key")

	km1, err := newWithBits(keyPath, testKeyBits)
	if err != nil {
		t.Fatalf("first newWithBits: %v", err)
	}

	km2, err := newWithBits(keyPath, testKeyBits)
	if err != nil {
		t.Fatalf("second newWithBits: %v", err)
	}

	if km1.PublicKey().N.Cmp(km2.PublicKey().N) != 0 {
		t.Fatal("reloaded key has a different modulus N: key was regenerated instead of loaded from disk")
	}
}

// TestPublicKeyPEMParses verifies that PublicKeyPEM returns a well-formed PKIX PEM block
// that parses back into an *rsa.PublicKey with the same modulus and exponent.
func TestPublicKeyPEMParses(t *testing.T) {
	km := newTestManager(t)

	pemStr := km.PublicKeyPEM()

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("pem.Decode found no PEM block in PublicKeyPEM output")
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("PEM block type: got %q, want %q", block.Type, "PUBLIC KEY")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey: %v", err)
	}

	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("parsed key type: got %T, want *rsa.PublicKey", parsed)
	}

	want := km.PublicKey()
	if rsaPub.N.Cmp(want.N) != 0 {
		t.Fatal("parsed public key modulus N does not match the manager's public key")
	}
	if rsaPub.E != want.E {
		t.Fatalf("parsed public key exponent E: got %d, want %d", rsaPub.E, want.E)
	}
}
