package fallback_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/fallback"
)

// knownProfile is the canonical profile the fake fallback server returns.
var knownProfile = fallback.Profile{
	ID:   "deadbeefdeadbeefdeadbeefdeadbeef",
	Name: "FallbackPlayer",
	Properties: []json.RawMessage{
		json.RawMessage(`{"name":"textures","value":"dGVzdA==","signature":"fakesig"}`),
	},
}

// fakeFallbackServer spins up an httptest.Server that mimics a Yggdrasil session server.
// It tracks the number of requests received so tests can assert cache behaviour.
type fakeFallbackServer struct {
	srv      *httptest.Server
	requests atomic.Int64 // incremented on every real hit (not from cache)
}

func newFakeFallbackServer(t *testing.T) *fakeFallbackServer {
	t.Helper()
	f := &fakeFallbackServer{}
	mux := http.NewServeMux()

	// hasJoined: returns known profile when username matches, 204 otherwise.
	mux.HandleFunc("/session/minecraft/hasJoined", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		username := r.URL.Query().Get("username")
		if username != knownProfile.Name {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(knownProfile)
	})

	// profile/{id}: returns known profile when UUID matches, 204 otherwise.
	mux.HandleFunc("/session/minecraft/profile/", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		uuid := r.URL.Path[len("/session/minecraft/profile/"):]
		if uuid != knownProfile.ID {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(knownProfile)
	})

	// nameToUUID: returns known id when name matches, 404 otherwise.
	mux.HandleFunc("/users/profiles/minecraft/", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		name := r.URL.Path[len("/users/profiles/minecraft/"):]
		if name != knownProfile.Name {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": knownProfile.ID, "name": knownProfile.Name})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// buildClient constructs a fallback.Client pointed at the fake server.
func buildClient(f *fakeFallbackServer, cacheTTL int) *fallback.Client {
	tr := true
	return fallback.NewClient([]config.FallbackAPIServer{
		{
			Nickname:             "fake",
			AccountURL:           f.srv.URL,
			SessionURL:           f.srv.URL,
			CacheTTLSeconds:      cacheTTL,
			DenyUnknownUsers:     false,
			EnableAuthentication: &tr,
		},
	})
}

// TestHasJoinedKnownPlayer verifies that HasJoined returns the fallback profile for a
// known username.
func TestHasJoinedKnownPlayer(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 0)

	p, idx, err := c.HasJoined(context.Background(), knownProfile.Name, "server1", "")
	if err != nil {
		t.Fatalf("HasJoined error: %v", err)
	}
	if p == nil {
		t.Fatal("HasJoined returned nil profile; want the known profile")
	}
	if p.ID != knownProfile.ID {
		t.Errorf("profile.ID = %q; want %q", p.ID, knownProfile.ID)
	}
	if p.Name != knownProfile.Name {
		t.Errorf("profile.Name = %q; want %q", p.Name, knownProfile.Name)
	}
	if idx != 0 {
		t.Errorf("serverIdx = %d; want 0", idx)
	}
}

// TestHasJoinedUnknownPlayer verifies that HasJoined returns nil for an unknown username.
func TestHasJoinedUnknownPlayer(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 0)

	p, _, err := c.HasJoined(context.Background(), "NoSuchPlayer", "server1", "")
	if err != nil {
		t.Fatalf("HasJoined error: %v", err)
	}
	if p != nil {
		t.Errorf("HasJoined returned non-nil profile for unknown player: %+v", p)
	}
}

// TestHasJoinedAuthDisabled verifies that a server with EnableAuthentication=false is
// skipped by HasJoined, returning nil.
func TestHasJoinedAuthDisabled(t *testing.T) {
	f := newFakeFallbackServer(t)

	disabledFalse := false
	c := fallback.NewClient([]config.FallbackAPIServer{
		{
			Nickname:             "disabled",
			SessionURL:           f.srv.URL,
			EnableAuthentication: &disabledFalse,
		},
	})

	p, _, err := c.HasJoined(context.Background(), knownProfile.Name, "server1", "")
	if err != nil {
		t.Fatalf("HasJoined error: %v", err)
	}
	if p != nil {
		t.Error("HasJoined should return nil when auth is disabled, got a profile")
	}
	if f.requests.Load() != 0 {
		t.Errorf("expected 0 requests to disabled server, got %d", f.requests.Load())
	}
}

// TestProfileByUUIDKnown verifies that ProfileByUUID returns the known profile.
func TestProfileByUUIDKnown(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 0)

	p, err := c.ProfileByUUID(context.Background(), knownProfile.ID)
	if err != nil {
		t.Fatalf("ProfileByUUID error: %v", err)
	}
	if p == nil {
		t.Fatal("ProfileByUUID returned nil for known UUID")
	}
	if p.ID != knownProfile.ID {
		t.Errorf("profile.ID = %q; want %q", p.ID, knownProfile.ID)
	}
	if len(p.Properties) == 0 {
		t.Error("profile has no properties; want at least one")
	}
}

// TestProfileByUUIDUnknown verifies that ProfileByUUID returns nil for an unknown UUID.
func TestProfileByUUIDUnknown(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 0)

	p, err := c.ProfileByUUID(context.Background(), "00000000000000000000000000000000")
	if err != nil {
		t.Fatalf("ProfileByUUID error: %v", err)
	}
	if p != nil {
		t.Errorf("ProfileByUUID returned non-nil for unknown UUID: %+v", p)
	}
}

// TestNameToUUIDKnown verifies that NameToUUID resolves the known player name.
func TestNameToUUIDKnown(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 0)

	id, ok, err := c.NameToUUID(context.Background(), knownProfile.Name)
	if err != nil {
		t.Fatalf("NameToUUID error: %v", err)
	}
	if !ok {
		t.Fatal("NameToUUID returned ok=false for known player")
	}
	if id != knownProfile.ID {
		t.Errorf("id = %q; want %q", id, knownProfile.ID)
	}
}

// TestNameToUUIDUnknown verifies that NameToUUID returns ok=false for an unknown name.
func TestNameToUUIDUnknown(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 0)

	_, ok, err := c.NameToUUID(context.Background(), "NoSuchPlayer")
	if err != nil {
		t.Fatalf("NameToUUID error: %v", err)
	}
	if ok {
		t.Error("NameToUUID returned ok=true for unknown player")
	}
}

// TestCachePreventsSecondRequest verifies that a second identical HasJoined call within
// the TTL window does not hit the fake server again.
func TestCachePreventsSecondRequest(t *testing.T) {
	f := newFakeFallbackServer(t)
	// cacheTTL=60 means the first response is cached for 60 seconds.
	c := buildClient(f, 60)

	ctx := context.Background()
	p1, _, err := c.HasJoined(ctx, knownProfile.Name, "cacheServer", "")
	if err != nil || p1 == nil {
		t.Fatalf("first HasJoined failed: err=%v profile=%v", err, p1)
	}
	firstCount := f.requests.Load()

	p2, _, err := c.HasJoined(ctx, knownProfile.Name, "cacheServer", "")
	if err != nil || p2 == nil {
		t.Fatalf("second HasJoined failed: err=%v profile=%v", err, p2)
	}
	secondCount := f.requests.Load()

	if secondCount != firstCount {
		t.Errorf("server received %d additional requests; want 0 (response should have been cached)",
			secondCount-firstCount)
	}
}

// TestCacheProfileByUUID verifies that a cached profile lookup doesn't re-hit the server.
func TestCacheProfileByUUID(t *testing.T) {
	f := newFakeFallbackServer(t)
	c := buildClient(f, 60)

	ctx := context.Background()
	_, _ = c.ProfileByUUID(ctx, knownProfile.ID)
	after1 := f.requests.Load()
	_, _ = c.ProfileByUUID(ctx, knownProfile.ID)
	after2 := f.requests.Load()

	if after2 != after1 {
		t.Errorf("expected no extra requests on cached profile lookup; got %d extra", after2-after1)
	}
}

// TestNewClientNilWhenEmpty verifies that NewClient returns nil for an empty server list,
// which is the feature-disabled signal.
func TestNewClientNilWhenEmpty(t *testing.T) {
	if c := fallback.NewClient(nil); c != nil {
		t.Error("NewClient(nil) should return nil")
	}
	if c := fallback.NewClient([]config.FallbackAPIServer{}); c != nil {
		t.Error("NewClient(empty) should return nil")
	}
}

// TestContextCancellation verifies that a cancelled context causes the call to return
// an error quickly rather than hanging.
func TestContextCancellation(t *testing.T) {
	// Use a slow server that blocks long enough for the cancel to fire.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until client times out; select with Done.
		<-r.Context().Done()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(slow.Close)

	tr := true
	c := fallback.NewClient([]config.FallbackAPIServer{
		{
			Nickname:             "slow",
			SessionURL:           slow.URL,
			EnableAuthentication: &tr,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// HasJoined should return quickly with nil profile (not hang).
	p, _, err := c.HasJoined(ctx, "anyone", "srv", "")
	_ = err // cancelled context -> error is expected
	if p != nil {
		t.Error("expected nil profile from cancelled context call")
	}
}
