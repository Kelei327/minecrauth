// SPDX-License-Identifier: Apache-2.0

// Package fallback implements a client for upstream Yggdrasil-compatible API servers
// used to support mixed-auth (e.g. local + Mojang players) and skin forwarding.
package fallback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/achetronic/minecrauth/internal/config"
)

// Profile is the raw Yggdrasil profile shape returned by a fallback server.
// Properties are kept as raw JSON so they can be passed through to clients verbatim,
// including the fallback server's original signature over the textures payload.
// We never re-sign these properties with our own key; callers must document that
// clients need to trust the fallback server's public key for texture verification.
type Profile struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties []json.RawMessage `json:"properties"`
}

// nameUUIDResponse is the Mojang-shape response for /users/profiles/minecraft/{name}.
type nameUUIDResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// cacheKey uniquely identifies a cached response.
type cacheKey struct {
	serverIdx int
	kind      string // "hasJoined", "profile", "nameUUID"
	param     string // username+serverID, uuid, or name
}

// cacheEntry holds a cached raw response body and its expiry.
type cacheEntry struct {
	body    []byte
	expires time.Time
}

// ttlCache is a simple in-memory TTL cache guarded by a mutex.
type ttlCache struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
}

func newTTLCache() *ttlCache {
	return &ttlCache{entries: make(map[cacheKey]cacheEntry)}
}

// get returns the cached body and true if the entry exists and has not expired.
func (c *ttlCache) get(k cacheKey) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, k)
		return nil, false
	}
	return e.body, true
}

// set stores body with the supplied TTL. A zero or negative TTL means no caching.
func (c *ttlCache) set(k cacheKey, body []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[k] = cacheEntry{body: body, expires: time.Now().Add(ttl)}
}

// Client performs HTTP calls against configured fallback Yggdrasil servers.
// A nil Client is safe to store; callers must check for nil before calling methods.
type Client struct {
	servers []config.FallbackAPIServer
	http    *http.Client
	cache   *ttlCache
}

// NewClient constructs a Client from the provided server list.
// Returns nil when servers is empty so callers can use a nil check as a feature flag.
func NewClient(servers []config.FallbackAPIServer) *Client {
	if len(servers) == 0 {
		return nil
	}
	return &Client{
		servers: servers,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: newTTLCache(),
	}
}

// HasJoined queries each configured fallback server's session endpoint for a pending
// join handshake. Servers with EnableAuthentication=false are skipped. Returns the first
// successful profile along with the index of the server that answered, or an error.
//
// The second return value (serverIdx) lets callers consult the server's DenyUnknownUsers
// policy without re-scanning the server list.
//
// ip is optional; pass an empty string when not available.
func (c *Client) HasJoined(ctx context.Context, username, serverID, ip string) (*Profile, int, error) {
	for i, srv := range c.servers {
		if !srv.AuthEnabled() {
			continue
		}
		if srv.SessionURL == "" {
			continue
		}

		url := srv.SessionURL + "/session/minecraft/hasJoined?username=" + username + "&serverId=" + serverID
		if ip != "" {
			url += "&ip=" + ip
		}

		k := cacheKey{serverIdx: i, kind: "hasJoined", param: username + "|" + serverID}
		ttl := time.Duration(srv.CacheTTLSeconds) * time.Second

		body, ok := c.cache.get(k)
		if !ok {
			resp, err := c.get(ctx, url)
			if err != nil {
				slog.Warn("fallback hasJoined: HTTP error",
					"server", srv.Nickname, "error", err)
				continue
			}
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
				// This server does not know this player; try the next one.
				continue
			}
			if resp.StatusCode != http.StatusOK {
				slog.Warn("fallback hasJoined: unexpected status",
					"server", srv.Nickname, "status", resp.StatusCode)
				continue
			}
			body, err = readBody(resp)
			if err != nil {
				slog.Warn("fallback hasJoined: reading body", "server", srv.Nickname, "error", err)
				continue
			}
			c.cache.set(k, body, ttl)
		}

		var p Profile
		if err := json.Unmarshal(body, &p); err != nil {
			slog.Warn("fallback hasJoined: decoding profile", "server", srv.Nickname, "error", err)
			continue
		}
		if p.ID == "" {
			continue
		}
		return &p, i, nil
	}
	return nil, -1, nil
}

// ProfileByUUID queries each configured fallback server's session endpoint for a profile
// by undashed UUID. Returns the first successful profile, or nil when none of the
// fallback servers know the UUID.
func (c *Client) ProfileByUUID(ctx context.Context, undashedUUID string) (*Profile, error) {
	for i, srv := range c.servers {
		if srv.SessionURL == "" {
			continue
		}

		url := srv.SessionURL + "/session/minecraft/profile/" + undashedUUID

		k := cacheKey{serverIdx: i, kind: "profile", param: undashedUUID}
		ttl := time.Duration(srv.CacheTTLSeconds) * time.Second

		body, ok := c.cache.get(k)
		if !ok {
			resp, err := c.get(ctx, url)
			if err != nil {
				slog.Warn("fallback profileByUUID: HTTP error",
					"server", srv.Nickname, "uuid", undashedUUID, "error", err)
				continue
			}
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				slog.Warn("fallback profileByUUID: unexpected status",
					"server", srv.Nickname, "status", resp.StatusCode)
				continue
			}
			body, err = readBody(resp)
			if err != nil {
				slog.Warn("fallback profileByUUID: reading body", "server", srv.Nickname, "error", err)
				continue
			}
			c.cache.set(k, body, ttl)
		}

		var p Profile
		if err := json.Unmarshal(body, &p); err != nil {
			slog.Warn("fallback profileByUUID: decoding profile", "server", srv.Nickname, "error", err)
			continue
		}
		if p.ID == "" {
			continue
		}
		return &p, nil
	}
	return nil, nil
}

// NameToUUID queries each configured fallback server's account endpoint to resolve a
// player name to an undashed UUID. Returns the undashed UUID and true when found.
func (c *Client) NameToUUID(ctx context.Context, name string) (string, bool, error) {
	for i, srv := range c.servers {
		if srv.AccountURL == "" {
			continue
		}

		url := srv.AccountURL + "/users/profiles/minecraft/" + name

		k := cacheKey{serverIdx: i, kind: "nameUUID", param: strings.ToLower(name)}
		ttl := time.Duration(srv.CacheTTLSeconds) * time.Second

		body, ok := c.cache.get(k)
		if !ok {
			resp, err := c.get(ctx, url)
			if err != nil {
				slog.Warn("fallback nameToUUID: HTTP error",
					"server", srv.Nickname, "name", name, "error", err)
				continue
			}
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				slog.Warn("fallback nameToUUID: unexpected status",
					"server", srv.Nickname, "status", resp.StatusCode)
				continue
			}
			body, err = readBody(resp)
			if err != nil {
				slog.Warn("fallback nameToUUID: reading body", "server", srv.Nickname, "error", err)
				continue
			}
			c.cache.set(k, body, ttl)
		}

		var nr nameUUIDResponse
		if err := json.Unmarshal(body, &nr); err != nil {
			slog.Warn("fallback nameToUUID: decoding response", "server", srv.Nickname, "error", err)
			continue
		}
		if nr.ID == "" {
			continue
		}
		return nr.ID, true, nil
	}
	return "", false, nil
}

// ServerAt returns the fallback server configuration at the given index.
// Panics if the index is out of range; callers should only use indices returned
// by HasJoined.
func (c *Client) ServerAt(idx int) config.FallbackAPIServer {
	return c.servers[idx]
}

// get performs a GET request with the client's shared http.Client, respecting ctx.
func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("request cancelled: %w", err)
		}
		return nil, fmt.Errorf("executing request: %w", err)
	}
	return resp, nil
}

// readBody reads and closes the response body, capping at 1 MiB.
func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	const maxBody = 1 << 20 // 1 MiB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return data, nil
}
