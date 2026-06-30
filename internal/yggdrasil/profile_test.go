package yggdrasil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achetronic/minecrauth/internal/signing"
	"github.com/achetronic/minecrauth/internal/store"
)

// newProfileTestKM generates a 2048-bit RSA key manager suitable for profile tests.
func newProfileTestKM(t *testing.T) *signing.KeyManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing RSA key: %v", err)
	}
	km, err := signing.New(path)
	if err != nil {
		t.Fatalf("loading KeyManager: %v", err)
	}
	return km
}

// makePlayer is a helper that creates a store.Player with optional skin/cape fields.
func makePlayer(name, uuid string, skinHash, skinModel, capeHash *string) *store.Player {
	return &store.Player{
		ID:        "test-id",
		UserID:    "user-id",
		Name:      name,
		UUID:      uuid,
		SkinHash:  skinHash,
		SkinModel: skinModel,
		CapeHash:  capeHash,
	}
}

// TestBuildProfileNoTextures verifies that a player with no skin or cape produces
// a profile whose textures map is empty (no SKIN or CAPE keys).
func TestBuildProfileNoTextures(t *testing.T) {
	km := newProfileTestKM(t)
	p := makePlayer("Steve", "550e8400-e29b-41d4-a716-446655440000", nil, nil, nil)

	profile, err := buildProfile(p, km, false, "http://auth.example.com", "")
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	if len(profile.Properties) == 0 {
		t.Fatal("expected at least one property")
	}
	prop := profile.Properties[0]
	textures := decodeTextures(t, prop.Value)

	if _, ok := textures["SKIN"]; ok {
		t.Error("expected no SKIN key when player has no skin hash")
	}
	if _, ok := textures["CAPE"]; ok {
		t.Error("expected no CAPE key when player has no cape hash")
	}
}

// TestBuildProfileClassicSkin verifies that a classic (Steve) skin produces a SKIN entry
// with the correct URL and no metadata object.
func TestBuildProfileClassicSkin(t *testing.T) {
	km := newProfileTestKM(t)
	skinHash := "deadbeefdeadbeef"
	skinModel := "classic"
	p := makePlayer("Steve", "550e8400-e29b-41d4-a716-446655440000", &skinHash, &skinModel, nil)

	profile, err := buildProfile(p, km, false, "http://auth.example.com", "")
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	textures := decodeTextures(t, profile.Properties[0].Value)

	skinEntry, ok := textures["SKIN"]
	if !ok {
		t.Fatal("expected SKIN key in textures map")
	}
	skinMap, ok := skinEntry.(map[string]any)
	if !ok {
		t.Fatalf("SKIN entry is not a map: %T", skinEntry)
	}

	gotURL, _ := skinMap["url"].(string)
	wantURL := "http://auth.example.com/textures/" + skinHash
	if gotURL != wantURL {
		t.Errorf("SKIN url = %q; want %q", gotURL, wantURL)
	}

	// Classic model must NOT have a metadata object.
	if _, hasMetadata := skinMap["metadata"]; hasMetadata {
		t.Error("classic skin must not have a metadata object")
	}

	if _, ok := textures["CAPE"]; ok {
		t.Error("expected no CAPE key when no cape hash is set")
	}
}

// TestBuildProfileSlimSkin verifies that a slim (Alex) skin produces a SKIN entry
// with metadata.model == "slim".
func TestBuildProfileSlimSkin(t *testing.T) {
	km := newProfileTestKM(t)
	skinHash := "cafebabecafebabe"
	skinModel := "slim"
	p := makePlayer("Alex", "12345678-1234-1234-1234-123456789abc", &skinHash, &skinModel, nil)

	profile, err := buildProfile(p, km, false, "https://mc.example.com", "")
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	textures := decodeTextures(t, profile.Properties[0].Value)
	skinEntry, ok := textures["SKIN"]
	if !ok {
		t.Fatal("expected SKIN key")
	}
	skinMap := skinEntry.(map[string]any)

	gotURL, _ := skinMap["url"].(string)
	if !strings.HasSuffix(gotURL, "/textures/"+skinHash) {
		t.Errorf("SKIN url %q does not end with /textures/%s", gotURL, skinHash)
	}

	meta, ok := skinMap["metadata"]
	if !ok {
		t.Fatal("slim skin must have a metadata object")
	}
	metaMap, ok := meta.(map[string]any)
	if !ok {
		t.Fatalf("metadata is not a map: %T", meta)
	}
	if metaMap["model"] != "slim" {
		t.Errorf("metadata.model = %q; want \"slim\"", metaMap["model"])
	}
}

// TestBuildProfileCape verifies that a player with a cape produces a CAPE entry in the
// textures map with the correct URL.
func TestBuildProfileCape(t *testing.T) {
	km := newProfileTestKM(t)
	capeHash := "c0ffee00c0ffee00"
	p := makePlayer("Alex", "12345678-1234-1234-1234-123456789abc", nil, nil, &capeHash)

	profile, err := buildProfile(p, km, false, "https://mc.example.com", "")
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	textures := decodeTextures(t, profile.Properties[0].Value)
	capeEntry, ok := textures["CAPE"]
	if !ok {
		t.Fatal("expected CAPE key")
	}
	capeMap := capeEntry.(map[string]any)
	gotURL, _ := capeMap["url"].(string)
	wantURL := "https://mc.example.com/textures/" + capeHash
	if gotURL != wantURL {
		t.Errorf("CAPE url = %q; want %q", gotURL, wantURL)
	}
}

// TestBuildProfileSignatureVerifies is the key canary: it builds a SIGNED profile
// with a skin set and verifies the RSA-SHA1 signature using the public key.
// A legitimately populated payload must produce a verifiable signature.
func TestBuildProfileSignatureVerifies(t *testing.T) {
	km := newProfileTestKM(t)
	skinHash := "aabbccddeeff0011"
	skinModel := "slim"
	p := makePlayer("Canary", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", &skinHash, &skinModel, nil)

	profile, err := buildProfile(p, km, true, "https://auth.test.com", "")
	if err != nil {
		t.Fatalf("buildProfile signed: %v", err)
	}

	if len(profile.Properties) == 0 {
		t.Fatal("expected properties in profile")
	}
	prop := profile.Properties[0]
	if prop.Signature == "" {
		t.Fatal("expected non-empty signature on signed profile")
	}

	// Verify the RSA-SHA1 signature against the public key.
	// This is exactly what authlib-injector and Minecraft clients do.
	sigBytes, err := base64.StdEncoding.DecodeString(prop.Signature)
	if err != nil {
		t.Fatalf("decoding signature base64: %v", err)
	}
	digest := sha1.Sum([]byte(prop.Value))
	if err := rsa.VerifyPKCS1v15(km.PublicKey(), crypto.SHA1, digest[:], sigBytes); err != nil {
		t.Fatalf("SIGNATURE VERIFICATION FAILED (canary): %v", err)
	}

	// Also verify the SKIN URL is present in the decoded payload.
	textures := decodeTextures(t, prop.Value)
	skinEntry, ok := textures["SKIN"]
	if !ok {
		t.Fatal("expected SKIN key in signed profile")
	}
	skinMap := skinEntry.(map[string]any)
	gotURL, _ := skinMap["url"].(string)
	if !strings.HasSuffix(gotURL, "/textures/"+skinHash) {
		t.Errorf("SKIN url %q does not end with /textures/%s", gotURL, skinHash)
	}
}

// TestBuildProfileUnsignedHasNoSignature verifies that unsigned profiles omit the
// signature field entirely (important for clients requesting unsigned profiles).
func TestBuildProfileUnsignedHasNoSignature(t *testing.T) {
	km := newProfileTestKM(t)
	p := makePlayer("Steve", "550e8400-e29b-41d4-a716-446655440000", nil, nil, nil)

	profile, err := buildProfile(p, km, false, "http://auth.example.com", "")
	if err != nil {
		t.Fatalf("buildProfile unsigned: %v", err)
	}

	for _, prop := range profile.Properties {
		if prop.Signature != "" {
			t.Errorf("unsigned profile has a non-empty signature on property %q", prop.Name)
		}
	}
}

// decodeTextures base64-decodes the property value and unmarshals the textures field.
func decodeTextures(t *testing.T, value string) map[string]any {
	t.Helper()
	jsonBytes, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decoding base64 property value: %v", err)
	}
	var payload struct {
		Textures map[string]any `json:"textures"`
	}
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		t.Fatalf("unmarshaling texture payload: %v", err)
	}
	return payload.Textures
}

// TestBuildProfileUploadableTextures is the Phase 1A canary: it verifies that the
// uploadableTextures property is appended with the correct comma-separated value
// per the allow-skins/allow-capes flags, that it is unsigned, and that it is omitted
// entirely when neither is allowed. A regression that drops or mis-orders the value
// must make this test fail.
func TestBuildProfileUploadableTextures(t *testing.T) {
	km := newProfileTestKM(t)
	p := makePlayer("Steve", "550e8400-e29b-41d4-a716-446655440000", nil, nil, nil)

	cases := []struct {
		name       string
		uploadable string
		wantValue  string
		wantProp   bool
	}{
		{"both", uploadableTexturesValue(true, true), "skin,cape", true},
		{"skin only", uploadableTexturesValue(true, false), "skin", true},
		{"cape only", uploadableTexturesValue(false, true), "cape", true},
		{"none", uploadableTexturesValue(false, false), "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := buildProfile(p, km, false, "http://auth.example.com", tc.uploadable)
			if err != nil {
				t.Fatalf("buildProfile: %v", err)
			}
			// The textures property must always remain first.
			if profile.Properties[0].Name != "textures" {
				t.Fatalf("Properties[0].Name = %q; want textures", profile.Properties[0].Name)
			}
			var found *TextureProperty
			for i := range profile.Properties {
				if profile.Properties[i].Name == "uploadableTextures" {
					found = &profile.Properties[i]
				}
			}
			if !tc.wantProp {
				if found != nil {
					t.Fatalf("expected no uploadableTextures property, got value %q", found.Value)
				}
				return
			}
			if found == nil {
				t.Fatal("expected uploadableTextures property, none found")
			}
			if found.Value != tc.wantValue {
				t.Errorf("uploadableTextures value = %q; want %q", found.Value, tc.wantValue)
			}
			if found.Signature != "" {
				t.Errorf("uploadableTextures must be unsigned, got signature %q", found.Signature)
			}
		})
	}
}
