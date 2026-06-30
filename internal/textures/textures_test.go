package textures_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
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

// crcChecksum computes a standard PNG CRC-32 over data, used when building synthetic
// PNG chunks in tests.
func crcChecksum(data []byte) uint32 {
	var table [256]uint32
	for n := 0; n < 256; n++ {
		c := uint32(n)
		for k := 0; k < 8; k++ {
			if c&1 != 0 {
				c = 0xedb88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[n] = c
	}
	c := uint32(0xffffffff)
	for _, b := range data {
		c = table[(c^uint32(b))&0xff] ^ (c >> 8)
	}
	return c ^ 0xffffffff
}

// buildChunk encodes a PNG chunk: 4-byte length, 4-byte type, payload, 4-byte CRC.
func buildChunk(typ string, payload []byte) []byte {
	var b bytes.Buffer
	l := uint32(len(payload))
	b.Write([]byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)})
	td := append([]byte(typ), payload...)
	b.Write(td)
	cv := crcChecksum(td)
	b.Write([]byte{byte(cv >> 24), byte(cv >> 16), byte(cv >> 8), byte(cv)})
	return b.Bytes()
}

// craftOversizedPNG builds a syntactically valid PNG header declaring w x h dimensions
// with a deliberately truncated IDAT, used to probe the decompression-bomb guard.
func craftOversizedPNG(w, h uint32) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	ihdr := []byte{
		byte(w >> 24), byte(w >> 16), byte(w >> 8), byte(w),
		byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h),
		8, 6, 0, 0, 0, // bit depth 8, color type 6 (RGBA), default compression/filter/interlace
	}
	b.Write(buildChunk("IHDR", ihdr))
	b.Write(buildChunk("IDAT", []byte{0x78, 0x9c, 0x01, 0x00})) // truncated zlib stream
	b.Write(buildChunk("IEND", nil))
	return b.Bytes()
}

// injectTextChunk inserts a tEXt chunk carrying keyword and text directly before the
// final IEND chunk of a valid PNG byte slice. The IEND chunk is always the last 12 bytes
// (4 length + 4 type + 0 payload + 4 CRC) of a valid PNG.
func injectTextChunk(pngData []byte, keyword, text string) []byte {
	payload := append([]byte(keyword), 0x00)
	payload = append(payload, []byte(text)...)
	chunk := buildChunk("tEXt", payload)
	// Insert just before the final 12 bytes (IEND chunk).
	split := len(pngData) - 12
	result := make([]byte, 0, len(pngData)+len(chunk))
	result = append(result, pngData[:split]...)
	result = append(result, chunk...)
	result = append(result, pngData[split:]...)
	return result
}

// TestDecodeAndSanitizeRejectsOversized verifies that DecodeAndSanitize rejects a
// crafted PNG that declares enormous dimensions in its header BEFORE any full decode
// attempt. The canary assertion checks that the error message mentions "exceed the
// maximum", which is only produced by the DecodeConfig dimension guard. If that guard
// were removed, png.Decode would fail later with a different error after attempting the
// gigabyte allocation, so the canary would catch the regression.
func TestDecodeAndSanitizeRejectsOversized(t *testing.T) {
	data := craftOversizedPNG(60000, 60000)

	// The crafted file must be tiny (far below 1 KiB) to prove it would otherwise trigger
	// a gigabyte allocation inside png.Decode.
	if len(data) > 200 {
		t.Fatalf("crafted bomb PNG is %d bytes; expected a tiny file (<= 200 bytes) that would allocate ~14 GB if decoded", len(data))
	}

	_, _, err := textures.DecodeAndSanitize(data)
	if err == nil {
		t.Fatal("DecodeAndSanitize should have rejected oversized PNG but returned nil error")
	}

	// Canary: the error must come from the header dimension check, not from png.Decode.
	// If the DecodeConfig guard is removed the error message will be different (e.g.
	// "not enough pixel data") and this assertion will fail.
	if !strings.Contains(err.Error(), "exceed the maximum") {
		t.Errorf("expected error to mention \"exceed the maximum\"; got: %v", err)
	}
}

// TestDecodeAndSanitizeStripsAncillaryChunks verifies that DecodeAndSanitize removes
// ancillary PNG chunks (tEXt, zTXt, etc.) from the output. This prevents hostile payloads
// embedded in uploaded textures from being served back to clients.
// The canary assertion fails if the re-encode step is removed.
func TestDecodeAndSanitizeStripsAncillaryChunks(t *testing.T) {
	base := generatePNG(t, 64, 64)

	const marker = "INJECTED_PAYLOAD_MARKER"
	input := injectTextChunk(base, "Comment", marker)

	// Sanity: the injection must be present in the raw input bytes.
	if !bytes.Contains(input, []byte(marker)) {
		t.Fatal("sanity check failed: injected tEXt chunk marker not found in crafted input")
	}

	out, _, err := textures.DecodeAndSanitize(input)
	if err != nil {
		t.Fatalf("DecodeAndSanitize returned unexpected error: %v", err)
	}

	// Canary: the sanitized output must NOT carry the injected marker.
	if bytes.Contains(out, []byte(marker)) {
		t.Error("sanitized PNG still contains injected ancillary chunk payload; re-encoding did not strip it")
	}

	// The output must still be a valid 64x64 PNG.
	cfg, err := png.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not a valid PNG: %v", err)
	}
	if cfg.Width != 64 || cfg.Height != 64 {
		t.Errorf("output dimensions are %dx%d; want 64x64", cfg.Width, cfg.Height)
	}
}

// TestDecodeAndSanitizeValidSkin verifies the happy path: a well-formed 64x64 skin PNG
// passes DecodeAndSanitize and produces non-empty sanitized bytes and a 64x64 image.
func TestDecodeAndSanitizeValidSkin(t *testing.T) {
	input := generatePNG(t, 64, 64)

	out, img, err := textures.DecodeAndSanitize(input)
	if err != nil {
		t.Fatalf("DecodeAndSanitize returned unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Error("sanitized PNG bytes are empty")
	}
	if img == nil {
		t.Fatal("returned image is nil")
	}
	b := img.Bounds()
	if b.Dx() != 64 || b.Dy() != 64 {
		t.Errorf("image bounds are %dx%d; want 64x64", b.Dx(), b.Dy())
	}
}
