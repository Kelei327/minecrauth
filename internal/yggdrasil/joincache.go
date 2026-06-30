package yggdrasil

import (
	"sync"
	"time"
)

// joinTTL is how long a pending join entry stays valid.
// The vanilla server's /hasJoined call arrives within a few seconds of /join;
// 30 s gives generous tolerance without keeping stale entries indefinitely.
const joinTTL = 30 * time.Second

// joinEntry records the player information stored when a client calls /join.
type joinEntry struct {
	profileName string
	profileUUID string // dashed canonical UUID stored in the DB
	expires     time.Time
}

// joinCache is an in-memory short-term store of pending join handshakes keyed by serverId.
// It does not survive restarts; that is intentional because the vanilla handshake always
// completes within a single session, and persistence would create a security risk.
type joinCache struct {
	mu      sync.Mutex
	entries map[string]joinEntry
}

// newJoinCache returns an initialised, empty join cache.
func newJoinCache() *joinCache {
	return &joinCache{entries: make(map[string]joinEntry)}
}

// set records a pending join for serverID. An existing entry for the same serverID is
// overwritten, which correctly handles the case of a client reconnecting to the same server.
func (c *joinCache) set(serverID, name, uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[serverID] = joinEntry{
		profileName: name,
		profileUUID: uuid,
		expires:     time.Now().Add(joinTTL),
	}
}

// get looks up the join entry for serverID. It returns the entry and true when the entry
// exists and has not yet expired. Expired entries are deleted lazily on this call.
// The entry is NOT consumed so that a server retry within the TTL window still succeeds.
func (c *joinCache) get(serverID string) (joinEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[serverID]
	if !ok {
		return joinEntry{}, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, serverID)
		return joinEntry{}, false
	}
	return e, true
}
