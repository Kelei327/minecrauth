package yggdrasil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// certificateTTL is the lifetime of an ephemeral player keypair issued by this endpoint.
// Minecraft 1.19+ launchers request new keys well before expiry; 48 hours matches the
// reference implementation (drasl/unmojang).
const certificateTTL = 48 * time.Hour

// certKeyPair holds the PEM-encoded ephemeral RSA keypair returned to the launcher.
type certKeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// certificatesResponse is the response body for POST /minecraftservices/player/certificates.
// Both v1 and v2 signatures are produced with the server's RSA signing key so that
// authlib-injector clients can verify them against the public key advertised in metadata.
type certificatesResponse struct {
	KeyPair              certKeyPair `json:"keyPair"`
	PublicKeySignature   string      `json:"publicKeySignature"`
	PublicKeySignatureV2 string      `json:"publicKeySignatureV2"`
	ExpiresAt            string      `json:"expiresAt"`
	RefreshedAfter       string      `json:"refreshedAfter"`
}

// wrap76 splits s into lines of at most 76 characters joined by "\n".
// The last line may be shorter. No trailing newline is appended by this helper.
// This matches the line width used by Java's Base64.getMimeEncoder(76, ...) which
// Minecraft's certificate verification code expects for the v1 signature input.
func wrap76(s string) string {
	const width = 76
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i += width {
		if i > 0 {
			b.WriteByte('\n')
		}
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// handlePlayerCertificates processes POST /minecraftservices/player/certificates.
// It requires a valid Bearer access token bound to a player profile. It generates an
// ephemeral 2048-bit RSA keypair, signs the public key twice with the server's signing
// key (v1 for MC 1.19; v2 for MC 1.19.1+), and returns the full certificate bundle.
func (h *Handler) handlePlayerCertificates(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeYggError(w, http.StatusUnauthorized, "ForbiddenOperationException", "Invalid token.", "")
		return
	}
	accessToken := strings.TrimPrefix(authz, "Bearer ")
	if accessToken == "" {
		writeYggError(w, http.StatusUnauthorized, "ForbiddenOperationException", "Invalid token.", "")
		return
	}

	tok, err := h.tokens.Lookup(r.Context(), accessToken)
	if err != nil {
		writeYggError(w, http.StatusUnauthorized, "ForbiddenOperationException", "Invalid token.", "")
		return
	}

	if tok.PlayerID == nil {
		writeYggError(w, http.StatusUnauthorized, "ForbiddenOperationException", "Token has no bound profile.", "")
		return
	}

	player, err := h.accounts.GetPlayer(r.Context(), *tok.PlayerID)
	if err != nil {
		slog.Error("handlePlayerCertificates: looking up player", "playerID", *tok.PlayerID, "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	// Generate an ephemeral 2048-bit RSA keypair for this player.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("handlePlayerCertificates: generating RSA key", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	// Private key PEM: PKCS8 DER bytes under "RSA PRIVATE KEY" label (Minecraft accepts this).
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		slog.Error("handlePlayerCertificates: marshaling private key", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}))

	// Public key PEM: SPKI/PKIX DER bytes under "RSA PUBLIC KEY" label.
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		slog.Error("handlePlayerCertificates: marshaling public key", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubDER}))

	// Compute timestamps.
	now := time.Now().UTC()
	expiresAt := now.Add(certificateTTL)
	refreshedAfter := now
	expiresAtMilli := expiresAt.UnixMilli()

	// v1 signature (MC 1.19): SHA1withRSA over the string "<expiresAtMilli><pubMojangPEM>".
	// pubMojangPEM is the public key in base64 wrapped at 76 cols (Java MIME encoder style)
	// surrounded by "RSA PUBLIC KEY" PEM headers. Go's pem.EncodeToMemory wraps at 64 cols,
	// so we must re-encode manually to produce the 76-col wrapping Minecraft expects.
	b64DER := base64.StdEncoding.EncodeToString(pubDER)
	pubMojangPEM := "-----BEGIN RSA PUBLIC KEY-----\n" + wrap76(b64DER) + "\n-----END RSA PUBLIC KEY-----\n"

	v1Input := []byte(fmt.Sprintf("%d%s", expiresAtMilli, pubMojangPEM))
	sigV1Raw, err := h.keys.SignSHA1(v1Input)
	if err != nil {
		slog.Error("handlePlayerCertificates: signing v1", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}
	publicKeySignature := base64.StdEncoding.EncodeToString(sigV1Raw)

	// v2 signature (MC 1.19.1+): SHA1withRSA over a 24+len(pubDER) byte buffer:
	//   bytes [0:16)  - player UUID as 16 raw bytes (big-endian, via hex.DecodeString).
	//   bytes [16:24) - expiresAtMilli as uint64 big-endian.
	//   bytes [24:)   - pubDER appended verbatim.
	// hex.DecodeString is used (not math/big) to preserve leading zero bytes in UUIDs.
	uuidBytes, err := hex.DecodeString(undash(player.UUID))
	if err != nil {
		slog.Error("handlePlayerCertificates: decoding player UUID hex", "uuid", player.UUID, "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}
	if len(uuidBytes) != 16 {
		slog.Error("handlePlayerCertificates: unexpected UUID byte length", "uuid", player.UUID, "len", len(uuidBytes))
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	buf := make([]byte, 0, 24+len(pubDER))
	buf = append(buf, uuidBytes...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(expiresAtMilli))
	buf = append(buf, ts...)
	buf = append(buf, pubDER...)

	sigV2Raw, err := h.keys.SignSHA1(buf)
	if err != nil {
		slog.Error("handlePlayerCertificates: signing v2", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}
	publicKeySignatureV2 := base64.StdEncoding.EncodeToString(sigV2Raw)

	slog.Debug("handlePlayerCertificates: issued player certificates", "uuid", player.UUID)

	writeJSON(w, http.StatusOK, certificatesResponse{
		KeyPair: certKeyPair{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
		},
		PublicKeySignature:   publicKeySignature,
		PublicKeySignatureV2: publicKeySignatureV2,
		ExpiresAt:            expiresAt.Format(time.RFC3339Nano),
		RefreshedAfter:       refreshedAfter.Format(time.RFC3339Nano),
	})
}
