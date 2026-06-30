// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/metrics"
)

// sessionCookieName is the name of the HttpOnly browser session cookie.
const sessionCookieName = "minecrauth_session"

// responseRecorder wraps http.ResponseWriter to capture the status code written by
// the downstream handler so request logger middleware can log it after the fact.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader captures the status and delegates to the underlying writer.
func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// requestLogger logs method, path, status code, elapsed milliseconds, and client IP
// for every handled request at slog Info level.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip logging for health, readiness, and metrics endpoints to prevent log flooding.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", clientIP(r),
		)
	})
}

// metricsMiddleware tracks request duration and total counts for prometheus metrics.
func metricsMiddleware(m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := newResponseRecorder(w)
			next.ServeHTTP(rec, r)

			route := r.Pattern
			if route == "" {
				route = "other"
			}

			m.Observe(r.Method, route, rec.status, time.Since(start))
		})
	}
}

// bodyLimit wraps the request body with http.MaxBytesReader so that bodies
// exceeding limitBytes cause downstream reads to return *http.MaxBytesError.
func bodyLimit(limitBytes int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, int64(limitBytes))
			next.ServeHTTP(w, r)
		})
	}
}

// aliHeader sets the authlib-injector API Location Indication (ALI) response header on
// every response. The value is the absolute URL of the Yggdrasil API, letting launchers
// discover the real endpoint from any address served by this instance. An empty location
// disables the header.
// Ref: https://yushijinhun.github.io/authlib-injector/en/yggdrasil-server-technical-specification.html
func aliHeader(location string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if location != "" {
				w.Header().Set("X-Authlib-Injector-API-Location", location)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limiterEntry bundles a rate.Limiter with the last access time used for cleanup.
type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// limiterStore holds per-IP token-bucket rate limiters. It is safe for concurrent use.
// A background goroutine (started by cleanupLoop) periodically evicts stale entries to
// prevent unbounded memory growth from clients that never send a second request.
type limiterStore struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	rps     rate.Limit
	burst   int
}

func newLimiterStore(rps float64, burst int) *limiterStore {
	return &limiterStore{
		entries: make(map[string]*limiterEntry),
		rps:     rate.Limit(rps),
		burst:   burst,
	}
}

// getLimiter returns the existing limiter for ip or creates a fresh one.
func (ls *limiterStore) getLimiter(ip string) *rate.Limiter {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	e, ok := ls.entries[ip]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(ls.rps, ls.burst)}
		ls.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter
}

// cleanup removes entries that have not been seen for more than 10 minutes.
func (ls *limiterStore) cleanup() {
	cutoff := time.Now().Add(-10 * time.Minute)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for ip, e := range ls.entries {
		if e.lastSeen.Before(cutoff) {
			delete(ls.entries, ip)
		}
	}
}

// cleanupLoop runs until ctx is cancelled, periodically evicting stale limiters.
func (ls *limiterStore) cleanupLoop(ctx interface{ Done() <-chan struct{} }) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ls.cleanup()
		}
	}
}

// rateLimit returns a middleware that enforces token-bucket rate limiting per client IP.
// Requests whose URL path starts with any of the provided exemptPrefixes are allowed
// through unconditionally without consuming any tokens. This is used to exempt the
// game-critical sessionserver routes (join handshake, profile lookups) from throttling so
// active gameplay is never interrupted, while still rate-limiting auth and management
// endpoints.
func rateLimit(ls *limiterStore, exemptPrefixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range exemptPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			ip := clientIP(r)
			l := ls.getLimiter(ip)
			if !l.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintf(w, `{"error":"TooManyRequests","message":"rate limit exceeded"}`)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// setBasicChallenge writes the WWW-Authenticate header that asks a client for
// HTTP Basic credentials. It is SKIPPED for browser XHR requests (identified by
// the X-Requested-With header the SPA sets): emitting it there would trigger the
// browser's native Basic-auth popup instead of letting the SPA redirect to its
// own login view. Programmatic clients (curl, scripts) still get the challenge.
func setBasicChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="minecrauth"`)
}

// basicAuth returns a middleware that authenticates requests using HTTP Basic credentials
// verified via authn. On success the authenticated *store.User is stored in the request
// context (accessible via userFromContext). When requireAdmin is true, an authenticated
// non-admin receives 403 Forbidden. Unauthenticated or invalid requests receive 401 with
// a WWW-Authenticate challenge.
func basicAuth(authn auth.Authenticator, requireAdmin bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			email, password, ok := r.BasicAuth()
			if !ok || email == "" {
				setBasicChallenge(w, r)
				writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
				return
			}

			user, err := authn.Authenticate(r.Context(), email, password)
			if err != nil {
				if errors.Is(err, auth.ErrInvalidCredentials) {
					setBasicChallenge(w, r)
					writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
					return
				}
				slog.Error("basicAuth: authenticating user", "email", email, "error", err)
				writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
				return
			}

			if requireAdmin && !user.IsAdmin {
				writeErrorJSON(w, http.StatusForbidden, "Forbidden", "admin access required")
				return
			}

			next.ServeHTTP(w, r.WithContext(contextWithUser(r.Context(), user)))
		})
	}
}

// isMutating reports whether an HTTP method has side effects (write semantics).
// CSRF protection is only applied to these methods.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// clearSessionCookie writes a Set-Cookie header that immediately expires the
// browser session cookie, effectively logging the browser out.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// sessionOrBasicAuth returns a middleware that authenticates requests first by
// looking for the minecrauth_session cookie (browser session), then falling back
// to HTTP Basic credentials. This allows the same API surface to serve both the
// Vue Web UI (cookie auth) and programmatic clients (Basic auth) without forking
// the route table.
//
// Cookie path:
//  1. Read the minecrauth_session cookie.
//  2. Validate the session (ErrInvalidSession → 401 + clear cookie).
//  3. Load the fresh user record from the store (blocked check → 401 + clear cookie).
//  4. For mutating methods (POST/PUT/PATCH/DELETE): require X-CSRF-Token header
//     to match the session CSRF token via constant-time compare (mismatch → 403).
//  5. Put the user in the request context.
//
// Basic auth path (no cookie or empty cookie):
//  1. Parse HTTP Basic credentials.
//  2. Authenticate via authn (includes blocked check in PasswordAuthenticator).
//  3. No CSRF requirement – Basic credentials on every request are self-authenticating.
//  4. Put the user in the request context.
//
// requireAdmin: after authentication, non-admin users receive 403 Forbidden.
func sessionOrBasicAuth(
	authn auth.Authenticator,
	sessions *auth.SessionManager,
	svc *accounts.Service,
	requireAdmin bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err == nil && cookie.Value != "" {
				// --- Cookie path ---
				sess, valErr := sessions.Validate(r.Context(), cookie.Value)
				if valErr != nil {
					clearSessionCookie(w)
					writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
					return
				}

				// Load the user fresh from the service so the blocked flag is current.
				user, loadErr := svc.GetUser(r.Context(), sess.UserID)
				if loadErr != nil {
					clearSessionCookie(w)
					writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
					return
				}
				if user.Blocked {
					_ = sessions.Revoke(r.Context(), sess.Token)
					clearSessionCookie(w)
					writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
					return
				}

				// CSRF check for mutating methods.
				if isMutating(r.Method) {
					provided := r.Header.Get("X-CSRF-Token")
					if !auth.ValidCSRF(sess.CSRFToken, provided) {
						writeErrorJSON(w, http.StatusForbidden, "Forbidden", "missing or invalid CSRF token")
						return
					}
				}

				if requireAdmin && !user.IsAdmin {
					writeErrorJSON(w, http.StatusForbidden, "Forbidden", "admin access required")
					return
				}

				ctx := contextWithUser(r.Context(), user)
				ctx = contextWithSession(ctx, sess)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// --- Basic auth fallback ---
			basicAuth(authn, requireAdmin)(next).ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client's IP from RemoteAddr, discarding the port.
// It does NOT trust X-Forwarded-For to avoid IP spoofing attacks that would
// allow a client to bypass per-IP rate limiting by cycling header values.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
