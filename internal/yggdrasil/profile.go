// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package yggdrasil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/achetronic/minecrauth/internal/signing"
	"github.com/achetronic/minecrauth/internal/store"
)

// undash removes the four dashes from a canonical 36-character UUID string and returns
// the compact 32-hex-character form used on the Yggdrasil wire.
func undash(uuid string) string {
	return strings.ReplaceAll(uuid, "-", "")
}

// redash inserts dashes into a 32-hex UUID string at the canonical 8-4-4-4-12 positions,
// returning the standard dashed UUID form expected by the store.
// If the input length is not 32, it is returned unchanged.
func redash(hex string) string {
	if len(hex) != 32 {
		return hex
	}
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}

// texturePayload is the JSON structure base64-encoded into the textures property value.
// Ref: https://minecraft.wiki/w/Mojang_API#UUID_to_Profile_and_Skin/Cape
type texturePayload struct {
	Timestamp   int64          `json:"timestamp"`
	ProfileID   string         `json:"profileId"`
	ProfileName string         `json:"profileName"`
	Textures    map[string]any `json:"textures"`
}

// rawFullProfile is the profile shape used when injecting fallback server properties
// verbatim. Because fallback properties are already signed by the fallback's RSA key
// (not ours), we cannot use FullProfile's typed TextureProperty slice; we must carry
// the raw JSON bytes through so the original signature is preserved.
//
// Signing implication: when this type is returned the client verifies the signature
// in each property against the fallback server's public key, not ours. Operators must
// ensure clients trust the fallback's key (e.g. via authlib-injector skinDomains or
// its multi-key feature). Our own RSA signing key is NOT involved.
type rawFullProfile struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties []json.RawMessage `json:"properties"`
}

// uploadableTexturesValue returns the comma-separated list of texture types the
// server permits uploading, in the order "skin","cape". It returns an empty
// string when no texture type is allowed, in which case the uploadableTextures
// profile property must be omitted entirely.
func uploadableTexturesValue(allowSkins, allowCapes bool) string {
	var types []string
	if allowSkins {
		types = append(types, "skin")
	}
	if allowCapes {
		types = append(types, "cape")
	}
	return strings.Join(types, ",")
}

// buildProfile constructs a FullProfile for the given player.
// baseURL is the external root URL (e.g. "https://auth.example.com") and is used to
// form texture URLs. When signed is true the textures property carries an RSA SHA1
// signature produced by km.SignProperty; when false the signature field is omitted.
func buildProfile(p *store.Player, km *signing.KeyManager, signed bool, baseURL string, uploadable string) (FullProfile, error) {
	undashed := undash(p.UUID)

	texMap := buildTexturesMap(p, baseURL)

	payload := texturePayload{
		Timestamp:   time.Now().UnixMilli(),
		ProfileID:   undashed,
		ProfileName: p.Name,
		Textures:    texMap,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return FullProfile{}, fmt.Errorf("marshaling texture payload: %w", err)
	}

	// The value field is the standard-base64 encoding of the payload JSON.
	// SignProperty signs this string (not the raw JSON bytes).
	value := base64.StdEncoding.EncodeToString(payloadJSON)

	prop := TextureProperty{
		Name:  "textures",
		Value: value,
	}

	if signed {
		sig, err := km.SignProperty(value)
		if err != nil {
			return FullProfile{}, fmt.Errorf("signing texture property: %w", err)
		}
		prop.Signature = sig
	}

	props := []TextureProperty{prop}
	if uploadable != "" {
		props = append(props, TextureProperty{
			Name:  "uploadableTextures",
			Value: uploadable,
		})
	}
	return FullProfile{
		ID:         undashed,
		Name:       p.Name,
		Properties: props,
	}, nil
}

// buildTexturesMap constructs the Textures map from the player's stored skin and cape
// hashes. The Yggdrasil spec requires SKIN/CAPE keys to be omitted entirely when not
// set. The "slim" model includes a metadata object; the classic (Steve) model does not.
// Ref: https://minecraft.wiki/w/Mojang_API#UUID_to_Profile_and_Skin/Cape
func buildTexturesMap(p *store.Player, baseURL string) map[string]any {
	m := map[string]any{}

	if p.SkinHash != nil && *p.SkinHash != "" {
		skinEntry := map[string]any{
			"url": baseURL + "/textures/" + *p.SkinHash,
		}
		// Only the "slim" (Alex) model carries a metadata object.
		// Classic (Steve) has no metadata per the Mojang spec.
		if p.SkinModel != nil && *p.SkinModel == "slim" {
			skinEntry["metadata"] = map[string]any{"model": "slim"}
		}
		m["SKIN"] = skinEntry
	}

	if p.CapeHash != nil && *p.CapeHash != "" {
		m["CAPE"] = map[string]any{
			"url": baseURL + "/textures/" + *p.CapeHash,
		}
	}

	return m
}

// playerHasSkin reports whether the player has a non-empty skin hash set.
func playerHasSkin(p *store.Player) bool {
	return p.SkinHash != nil && *p.SkinHash != ""
}
