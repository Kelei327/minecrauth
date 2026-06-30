package textures_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/achetronic/minecrauth/internal/textures"
)

// generatePNG encodes an RGBA image of the given dimensions as PNG bytes.
// Images are filled with a solid colour so the bytes are deterministic.
func generatePNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a non-transparent colour so the PNG is non-trivial.
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 0x3c, G: 0x7e, B: 0xff, A: 0xff})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("generatePNG: encoding %dx%d PNG: %v", width, height, err)
	}
	return buf.Bytes()
}

// TestPutGet verifies that a valid 64x64 PNG can be stored and retrieved unchanged.
func TestPutGet(t *testing.T) {
	dir := t.TempDir()
	ts, err := textures.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	skinPNG := generatePNG(t, 64, 64)

	hash, err := ts.Put(skinPNG)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if hash == "" {
		t.Fatal("Put returned empty hash")
	}

	got, err := ts.Get(hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, skinPNG) {
		t.Fatalf("Get returned %d bytes, want %d; bytes differ", len(got), len(skinPNG))
	}

	if !ts.Has(hash) {
		t.Error("Has should be true after Put")
	}
}

// TestPutDedup verifies that uploading the same PNG twice returns the same hash
// and that the second call does not attempt to write a new file (content-addressed dedup).
func TestPutDedup(t *testing.T) {
	dir := t.TempDir()
	ts, err := textures.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := generatePNG(t, 64, 64)

	hash1, err := ts.Put(data)
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// Make the directory read-only so any new write would fail.
	// The second Put must succeed by detecting the existing file.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	hash2, err := ts.Put(data)
	if err != nil {
		t.Fatalf("second Put (dedup) failed: %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("expected identical hashes on dedup; got %s and %s", hash1, hash2)
	}
}

// TestPutInvalidPNG verifies that non-PNG bytes are rejected by Put.
func TestPutInvalidPNG(t *testing.T) {
	dir := t.TempDir()
	ts, err := textures.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	garbage := []byte("this is not a PNG file at all")
	_, err = ts.Put(garbage)
	if err == nil {
		t.Fatal("Put should have rejected non-PNG data but returned nil error")
	}
}

// TestValidateSkinRejectsWrongDimensions checks that a 63x63 or otherwise
// mis-dimensioned image fails ValidateSkin.
func TestValidateSkinRejectsWrongDimensions(t *testing.T) {
	cases := []struct {
		name          string
		width, height int
		sizeLimit     int
		wantErr       bool
	}{
		{name: "valid 64x64", width: 64, height: 64, sizeLimit: 0, wantErr: false},
		{name: "valid 64x32 legacy", width: 64, height: 32, sizeLimit: 0, wantErr: false},
		{name: "valid 128x128 HD", width: 128, height: 128, sizeLimit: 0, wantErr: false},
		{name: "valid 128x64 HD legacy", width: 128, height: 64, sizeLimit: 0, wantErr: false},
		{name: "invalid 63x63", width: 63, height: 63, sizeLimit: 0, wantErr: true},
		{name: "invalid 64x63", width: 64, height: 63, sizeLimit: 0, wantErr: true},
		{name: "invalid 64x48 odd height", width: 64, height: 48, sizeLimit: 0, wantErr: true},
		{name: "invalid 32x32 too small", width: 32, height: 32, sizeLimit: 0, wantErr: true},
		{name: "128x128 exceeds sizeLimit=64", width: 128, height: 128, sizeLimit: 64, wantErr: true},
		{name: "64x64 equals sizeLimit=64", width: 64, height: 64, sizeLimit: 64, wantErr: false},
		{name: "sizeLimit=0 means unlimited", width: 256, height: 256, sizeLimit: 0, wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := image.NewRGBA(image.Rect(0, 0, tc.width, tc.height))
			err := textures.ValidateSkin(img, tc.sizeLimit)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateSkin(%dx%d, limit=%d) expected error, got nil", tc.width, tc.height, tc.sizeLimit)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateSkin(%dx%d, limit=%d) unexpected error: %v", tc.width, tc.height, tc.sizeLimit, err)
			}
		})
	}
}

// TestValidateCapeRejectsWrongDimensions checks that incorrect cape dimensions are rejected.
func TestValidateCapeRejectsWrongDimensions(t *testing.T) {
	cases := []struct {
		name          string
		width, height int
		wantErr       bool
	}{
		{name: "valid 64x32", width: 64, height: 32, wantErr: false},
		{name: "valid 128x64 HD", width: 128, height: 64, wantErr: false},
		{name: "invalid 64x64 square", width: 64, height: 64, wantErr: true},
		{name: "invalid 63x32 bad width", width: 63, height: 32, wantErr: true},
		{name: "invalid 64x33 bad height", width: 64, height: 33, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := image.NewRGBA(image.Rect(0, 0, tc.width, tc.height))
			err := textures.ValidateCape(img)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateCape(%dx%d) expected error, got nil", tc.width, tc.height)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateCape(%dx%d) unexpected error: %v", tc.width, tc.height, err)
			}
		})
	}
}

// TestGetRejectsTraversalHash verifies that Get refuses hashes containing
// path-traversal characters or non-hex content.
func TestGetRejectsTraversalHash(t *testing.T) {
	dir := t.TempDir()
	ts, err := textures.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	badHashes := []string{
		"../etc/passwd",
		"../../root/.ssh/id_rsa",
		"abc.xyz",
		"DEADBEEF",   // uppercase hex is rejected (reHex is lowercase only)
		"abc xyz",    // space
		"abc\x00xyz", // null byte
		"",           // empty
	}

	for _, h := range badHashes {
		t.Run(h, func(t *testing.T) {
			_, err := ts.Get(h)
			if err == nil {
				t.Errorf("Get(%q) should have returned an error for unsafe hash", h)
			}
		})
	}
}

// TestGetMissing verifies that Get returns an error when the hash does not exist.
func TestGetMissing(t *testing.T) {
	dir := t.TempDir()
	ts, err := textures.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	validButAbsentHash := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	_, err = ts.Get(validButAbsentHash)
	if err == nil {
		t.Error("Get with absent hash should return an error")
	}
}

// TestCapePNG verifies that a 64x32 PNG can be stored and retrieved.
func TestCapePNG(t *testing.T) {
	dir := t.TempDir()
	ts, err := textures.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	capePNG := generatePNG(t, 64, 32)
	hash, err := ts.Put(capePNG)
	if err != nil {
		t.Fatalf("Put cape: %v", err)
	}

	got, err := ts.Get(hash)
	if err != nil {
		t.Fatalf("Get cape: %v", err)
	}
	if !bytes.Equal(got, capePNG) {
		t.Error("retrieved cape bytes differ from uploaded bytes")
	}

	// Verify that the stored file is on disk where expected.
	expectedPath := filepath.Join(dir, hash+".png")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("expected texture file at %s: %v", expectedPath, err)
	}
}

// TestDetectModel verifies the slim/classic arm-width heuristic.
func TestDetectModel(t *testing.T) {
	// The classic-only arm pixels the detector samples (in 64x64 coordinates).
	classicOnly := [][2]int{
		{46, 20}, {47, 20}, {46, 31}, {47, 31},
		{54, 20}, {55, 20}, {54, 31}, {55, 31},
	}

	// A fully opaque skin must be detected as classic.
	classic := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			classic.Set(x, y, color.RGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff})
		}
	}
	if got := textures.DetectModel(classic); got != "classic" {
		t.Errorf("opaque skin: expected classic, got %q", got)
	}

	// A skin with the classic-only arm pixels transparent must be detected as slim.
	slim := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			slim.Set(x, y, color.RGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff})
		}
	}
	for _, p := range classicOnly {
		slim.Set(p[0], p[1], color.RGBA{0, 0, 0, 0})
	}
	if got := textures.DetectModel(slim); got != "slim" {
		t.Errorf("slim skin: expected slim, got %q", got)
	}
}
