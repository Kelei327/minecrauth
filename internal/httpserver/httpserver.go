// Package httpserver manages the HTTP server lifecycle, routing, and middleware.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/mailer"
	"github.com/achetronic/minecrauth/internal/metrics"
	"github.com/achetronic/minecrauth/internal/openapi"
	"github.com/achetronic/minecrauth/internal/signing"
	"github.com/achetronic/minecrauth/internal/store"
	"github.com/achetronic/minecrauth/internal/textures"
	"github.com/achetronic/minecrauth/internal/yggdrasil"
	"github.com/achetronic/minecrauth/webui"
)

// Deps groups all domain-layer dependencies required to build the HTTP server.
// Keeping them in a struct avoids a long positional argument list and makes future
// additions backwards-compatible.
type Deps struct {
	Accounts   *accounts.Service
	Tokens     *auth.TokenService
	Authn      auth.Authenticator
	Keys       *signing.KeyManager
	YggHandler *yggdrasil.Handler
	// Textures is the content-addressed texture store. May be nil when texture
	// features are not required (tests that do not exercise uploads/serving).
	Textures *textures.TextureStore
	// Sessions manages browser UI sessions for the Vue Web UI.
	Sessions *auth.SessionManager
	// Store is the underlying data store, needed by sessionOrBasicAuth to load
	// a fresh user record (including the Blocked flag) after session validation.
	Store store.Store
	// OIDCBrowser implements the OIDC authorization-code flow with PKCE for browser login.
	OIDCBrowser *auth.OIDCBrowserFlow
	// Mailer is the email delivery layer.
	Mailer mailer.Mailer
	// ConfigPath is the path to the configuration file (optional).
	ConfigPath string
}

// Server wraps an *http.Server together with the infrastructure (rate-limiter store)
// needed to manage its full lifecycle.
type Server struct {
	handler    http.Handler
	httpServer *http.Server
	ls         *limiterStore
}

// New builds the root handler and wraps it in a ready-to-use Server. The caller starts
// serving by calling Start(ctx).
func New(cfg *config.Config, deps Deps) (*Server, error) {
	ls := newLimiterStore(cfg.RateLimitRPS, cfg.RateLimitBurst)
	handler := buildRootHandler(cfg, deps, ls)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return &Server{
		handler:    handler,
		httpServer: httpSrv,
		ls:         ls,
	}, nil
}

// Handler returns the root http.Handler. Exposed so tests can wrap it in
// httptest.NewServer without going through a real TCP listen.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Start begins accepting connections and blocks until ctx is cancelled, at which point
// it performs a graceful shutdown with a 30-second timeout. A nil error is returned on
// clean shutdown; any listen or shutdown error is returned wrapped.
func (s *Server) Start(ctx context.Context) error {
	// Start the rate-limiter cleanup goroutine.
	go s.ls.cleanupLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("httpserver: listening", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("httpserver listen: %w", err)
		}
		return nil

	case <-ctx.Done():
		slog.Info("httpserver: shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("httpserver graceful shutdown: %w", err)
		}
		slog.Info("httpserver: stopped cleanly")
		return nil
	}
}

// buildRootHandler assembles the complete middleware + routing tree.
//
// Middleware chain (outermost -> innermost):
//
//	aliHeader -> requestLogger -> bodyLimit -> rateLimit(exempt: sessionserver) -> root mux
//
// Route table (before prefix stripping):
//
//	GET  /textures/{hash}         Texture file serving (content-addressed PNG)
//	GET  {yggPrefix}              Metadata document (path rewritten to /)
//	ANY  {yggPrefix}/...          Yggdrasil protocol (authserver + sessionserver + profiles)
//	POST {apiPrefix}/register     Self-service registration (no auth)
//	*    {apiPrefix}/...          Public management API (session or Basic auth, non-admin)
//	*    {adminPrefix}/...        Admin management API (session or Basic auth, admin required)
//	*    /web/api/...             Vue Web UI API (session cookie or Basic auth)
func buildRootHandler(cfg *config.Config, deps Deps, ls *limiterStore) http.Handler {
	m := metrics.New()
	mux := http.NewServeMux()

	// Texture serving: GET /textures/{hash} lives at the root because texture URLs
	// are <BaseURL>/textures/<hash> and BaseURL has no path prefix by convention.
	if deps.Textures != nil {
		mux.HandleFunc("GET /textures/{hash}", func(w http.ResponseWriter, r *http.Request) {
			hash := r.PathValue("hash")
			data, err := deps.Textures.Get(hash)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			// Immutable cache: same hash always means the same bytes.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		})
	}

	// Yggdrasil routes
	yggMux := deps.YggHandler.Routes()

	// Exact prefix match (no trailing slash) rewrites the path to "/" so the metadata
	// handler registered as "GET /{$}" in the yggdrasil mux is reachable without
	// a redirect. This is the path authlib-injector clients hit on startup.
	mux.Handle(cfg.YggdrasilPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		r2.URL.RawPath = "/"
		yggMux.ServeHTTP(w, r2)
	}))
	// Trailing-slash prefix: handles all sub-paths via StripPrefix.
	mux.Handle(cfg.YggdrasilPrefix+"/", http.StripPrefix(cfg.YggdrasilPrefix, yggMux))

	// Management API
	mh := newManagementHandler(deps.Accounts, deps.Authn, cfg, deps.Textures, deps.Sessions, deps.Tokens, deps.Store, deps.OIDCBrowser, deps.Mailer, deps.ConfigPath)

	if deps.OIDCBrowser != nil {
		mux.HandleFunc("GET /oauth/login", mh.handleOAuthLogin)
		mux.HandleFunc("GET /oauth/callback", mh.handleOAuthCallback)
	}

	// authlib-injector game texture API: Bearer-authenticated PUT/DELETE, mounted under the
	// Yggdrasil prefix. These method+full-path patterns are more specific than the prefix
	// handler registered above, so Go's ServeMux routes matching requests here.
	gameTexPattern := cfg.YggdrasilPrefix + "/api/user/profile/{uuid}/{textureType}"
	mux.HandleFunc("PUT "+gameTexPattern, mh.handleGameUploadTexture)
	mux.HandleFunc("DELETE "+gameTexPattern, mh.handleGameDeleteTexture)

	// Public API: StripPrefix reveals the sub-mux patterns (/register, /me, /me/players, ...).
	mux.Handle(cfg.ApiPrefix+"/", http.StripPrefix(cfg.ApiPrefix, mh.buildAPIMux()))

	// Admin API: sessionOrBasicAuth(requireAdmin=true) wraps the entire admin sub-mux so that
	// every admin route is gated before the sub-mux even sees the request.
	adminHandler := sessionOrBasicAuth(deps.Authn, deps.Sessions, deps.Accounts, true)(
		http.StripPrefix(cfg.AdminPrefix, mh.buildAdminMux()),
	)
	mux.Handle(cfg.AdminPrefix+"/", adminHandler)

	// Vue Web UI API: mounted at /web/api. StripPrefix reveals /login, /logout, /session, /config.
	mux.Handle(webAPIPrefix+"/", http.StripPrefix(webAPIPrefix, mh.buildWebAPIMux()))

	// OpenAPI Spec documentation routes.
	// The spec is served unauthenticated as it is API documentation and contains no secrets;
	// operators can gate it at the reverse proxy.
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(openapi.SpecJSON)
	})
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openapi.SpecYAML)
	})

	// Serve static assets under /static/
	staticFS := webui.FS()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	// SPA routes catch-all: serve index.html for GET /, /login, /account, /players, /admin-ui, /oauth-callback
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "/login" || path == "/account" || path == "/players" || path == "/admin-ui" || path == "/oauth-callback" || path == "/reset" || path == "/verify" {
			if r.Method != http.MethodGet {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			content, err := fs.ReadFile(staticFS, "index.html")
			if err != nil {
				http.Error(w, "index.html not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
			return
		}
		http.NotFound(w, r)
	})

	// Liveness check: GET /healthz
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Readiness check: GET /readyz
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if deps.Store == nil {
			slog.Warn("readyz: store is nil")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}

		if err := deps.Store.Ping(ctx); err != nil {
			slog.Warn("readyz: store ping failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Metrics endpoint: GET /metrics
	mux.Handle("GET /metrics", m.Handler())

	// Rate-limit exemptions. These paths are requested in bursts by legitimate clients
	// and must never be throttled:
	//   - the sessionserver subtree carries active gameplay (join handshake, profiles),
	//   - /static serves the Web UI assets (a single page load fetches ~15 ES modules),
	//   - /textures serves skin and cape PNGs, often many at once,
	//   - /healthz, /readyz, /metrics ops endpoints.
	rateLimitExempt := []string{
		cfg.YggdrasilPrefix + "/sessionserver",
		"/static",
		"/textures",
		"/healthz",
		"/readyz",
		"/metrics",
	}

	// ALI (API Location Indication): advertise the absolute Yggdrasil API URL on every
	// response so launchers can discover it from any address this instance serves.
	aliLocation := cfg.BaseURL + cfg.YggdrasilPrefix + "/"

	// Stack global middleware: log every request, enforce body size, rate-limit
	// everything except the exempt subtrees.
	return aliHeader(aliLocation)(
		requestLogger(
			metricsMiddleware(m)(
				bodyLimit(cfg.BodyLimitBytes)(
					rateLimit(ls, rateLimitExempt...)(mux),
				),
			),
		),
	)
}
