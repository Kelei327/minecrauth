// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

// Package textures implements content-addressed storage for Minecraft skin and cape PNG files.
// Files are stored as <dir>/<sha256-hex>.png and deduplicated by hash.
package textures

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
)

// reHex matches strings consisting solely of lowercase hexadecimal digits.
// Used to validate texture hashes and prevent path traversal in Get.
var reHex = regexp.MustCompile(`^[0-9a-f]+$`)

// MaxTextureDimension is the absolute ceiling, in pixels, for the width or height of any
// uploaded texture. It is a hard safety limit independent of the configurable skin size
// limit. image/png sizes its pixel buffer from the PNG header before reading pixel data,
// so a tiny crafted file declaring enormous dimensions can exhaust memory (a PNG
// decompression bomb). DecodeAndSanitize reads only the header first and rejects oversized
// images before any full decode. 1024 is far above any legitimate skin or HD skin.
const MaxTextureDimension = 1024

// TextureStore implements content-addressed storage for PNG texture files.
// Two uploads of identical bytes produce the same hash and only one file on disk.
type TextureStore struct {
	dir string
}

// New creates a TextureStore backed by dir, creating the directory if it does not exist.
func New(dir string) (*TextureStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating texture directory %s: %w", dir, err)
	}
	return &TextureStore{dir: dir}, nil
}

// Put validates that data is a well-formed PNG, computes its SHA-256 hex hash, writes
// <dir>/<hash>.png if the file is absent, and returns the hash string.
// Dimension validation is the caller's responsibility; use ValidateSkin or ValidateCape
// on the decoded image before calling Put.
func (ts *TextureStore) Put(data []byte) (string, error) {
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		return "", fmt.Errorf("data is not a valid PNG: %w", err)
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	path := filepath.Join(ts.dir, hash+".png")
	if _, err := os.Stat(path); err == nil {
		// File already exists; skip writing (content-addressed deduplication).
		return hash, nil
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("writing texture %s: %w", hash, err)
	}
	return hash, nil
}

// DecodeAndSanitize validates and normalizes raw PNG bytes for safe storage and serving.
//
// It first reads ONLY the PNG header (png.DecodeConfig) and rejects the image if its
// declared width or height exceeds MaxTextureDimension, BEFORE any full decode. This is
// the defense against PNG decompression bombs: a full png.Decode allocates a pixel buffer
// sized from the header, so the dimension check must happen on the header alone.
//
// It then fully decodes the image and re-encodes it with the standard encoder, which emits
// only the bitmap (IHDR/IDAT/IEND) and drops any ancillary chunks (tEXt, zTXt, etc.) that
// could carry hostile payloads to clients.
//
// It returns the sanitized PNG bytes (to be stored) and the decoded image (for dimension
// validation by the caller via ValidateSkin/ValidateCape). The returned bytes are what the
// caller must persist, NOT the original input.
func DecodeAndSanitize(data []byte) ([]byte, image.Image, error) {
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PNG header: %w", err)
	}
	if cfg.Width > MaxTextureDimension || cfg.Height > MaxTextureDimension {
		return nil, nil, fmt.Errorf("texture dimensions %dx%d exceed the maximum of %d pixels", cfg.Width, cfg.Height, MaxTextureDimension)
	}

	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PNG: %w", err)
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.DefaultCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, nil, fmt.Errorf("re-encoding sanitized PNG: %w", err)
	}
	return buf.Bytes(), img, nil
}

// Get returns the raw PNG bytes for the texture identified by hash.
// It rejects any hash that contains non-lowercase-hex characters to prevent
// path traversal attacks (e.g. "../etc/passwd").
func (ts *TextureStore) Get(hash string) ([]byte, error) {
	if !reHex.MatchString(hash) || hash == "" {
		return nil, fmt.Errorf("invalid texture hash %q: must be non-empty lowercase hex", hash)
	}
	path := filepath.Join(ts.dir, hash+".png")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("texture %q not found", hash)
		}
		return nil, fmt.Errorf("reading texture %q: %w", hash, err)
	}
	return data, nil
}

// Has reports whether a texture with the given hash exists in the store.
// Returns false for any hash that is not valid lowercase hex.
func (ts *TextureStore) Has(hash string) bool {
	if !reHex.MatchString(hash) || hash == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(ts.dir, hash+".png"))
	return err == nil
}

// ValidateSkin checks that img has dimensions acceptable for a Minecraft skin.
// Valid shapes are multiples of the 64x64 base (modern skins: width == height,
// both divisible by 64) or multiples of the 64x32 base (legacy skins: height == width/2,
// width divisible by 64). When skinSizeLimit > 0, the width must not exceed it.
// Ref: https://minecraft.wiki/w/Skin
func ValidateSkin(img image.Image, skinSizeLimit int) error {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 64 || w%64 != 0 {
		return fmt.Errorf("skin width %d is not a positive multiple of 64", w)
	}
	// Height must equal width (modern 64x64 base) or half of width (legacy 64x32 base).
	if h != w && h*2 != w {
		return fmt.Errorf("skin height %d must equal width %d (modern) or half of width (legacy)", h, w)
	}
	if skinSizeLimit > 0 && w > skinSizeLimit {
		return fmt.Errorf("skin width %d exceeds the configured limit of %d pixels", w, skinSizeLimit)
	}
	return nil
}

// DetectModel guesses whether a skin uses the "slim" (3px arms) or "classic" (4px
// arms) model by inspecting the arm pixels that only exist in the classic layout.
//
// On the 64x64 base layout, the classic right arm occupies columns 44..47. The slim
// arm is one pixel narrower, leaving a column of fully transparent pixels where the
// classic model would have opaque ones. We sample those classic-only pixels (scaled
// for HD skins): if they are all transparent the skin is slim, otherwise classic.
// This is a heuristic and can misjudge unusually authored skins, so callers should
// allow a manual override. Ref: https://minecraft.wiki/w/Skin
func DetectModel(img image.Image) string {
	b := img.Bounds()
	scale := b.Dx() / 64
	if scale < 1 {
		return "classic"
	}

	// Classic-only pixels (in 64x64 coordinates) along the right-arm and its overlay.
	// In the slim model these are transparent; in classic they are opaque.
	classicOnly := [][2]int{
		{46, 20}, {47, 20}, {46, 31}, {47, 31}, // arm top/bottom edge
		{54, 20}, {55, 20}, {54, 31}, {55, 31}, // arm overlay layer
	}

	for _, p := range classicOnly {
		x := p[0]*scale + b.Min.X
		y := p[1]*scale + b.Min.Y
		_, _, _, a := img.At(x, y).RGBA()
		if a > 0 {
			// Any opaque classic-only pixel means this is a classic skin.
			return "classic"
		}
	}
	return "slim"
}

// ValidateCape checks that img has dimensions acceptable for a Minecraft cape.
// Valid shapes are multiples of the 64x32 base (height == width/2, width divisible by 64).
// Ref: https://minecraft.wiki/w/Cape
func ValidateCape(img image.Image) error {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 64 || w%64 != 0 {
		return fmt.Errorf("cape width %d is not a positive multiple of 64", w)
	}
	if h*2 != w {
		return fmt.Errorf("cape height %d must be half of width %d", h, w)
	}
	return nil
}
