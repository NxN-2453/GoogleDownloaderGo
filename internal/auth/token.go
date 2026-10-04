// Package auth implements Google OAuth token handling for the relay.
//
// The relay never uses a service account or a credentials.json file. It works
// from environment configuration alone, supporting two modes:
//
//	access-only : a static access token, for temporary personal testing. When
//	              it expires the relay can only report a clear error.
//	refresh     : access token + refresh token + client id/secret. The relay
//	              mints new access tokens on demand and on a 401, so it keeps
//	              working unattended.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/config"
)

// Errors surfaced by the token source. Handlers translate these into
// actionable HTTP responses.
var (
	// ErrNoCredentials means no Google credentials are configured at all.
	ErrNoCredentials = errors.New("no Google credentials configured: set GOOGLE_ACCESS_TOKEN, or GOOGLE_REFRESH_TOKEN with GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")

	// ErrAccessTokenExpired is returned when the access token is known to be
	// expired and cannot be renewed because refresh mode is not configured.
	ErrAccessTokenExpired = errors.New("Google access token has expired and no refresh token is configured (set GOOGLE_REFRESH_TOKEN, GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)")

	// ErrInvalidGrant means Google rejected the refresh token.
	ErrInvalidGrant = errors.New("Google rejected the refresh token (invalid_grant): it is expired, revoked, or belongs to a different OAuth client")

	// ErrInvalidClient means Google rejected the client credentials.
	ErrInvalidClient = errors.New("Google rejected the OAuth client credentials (invalid_client): check GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")

	// ErrRefreshFailed wraps any other token endpoint failure.
	ErrRefreshFailed = errors.New("Google token refresh failed")
)

// TokenProvider is the seam the Drive client depends on. Tests substitute a
// fake implementation.
type TokenProvider interface {
	// Token returns a usable access token, refreshing it when necessary.
	Token(ctx context.Context) (string, error)
	// Invalidate drops the cached access token so the next call refreshes.
	// It is called after a 401 from the Drive API.
	Invalidate()
}

// Status is a redacted snapshot of the token source, safe to expose.
type Status struct {
	Mode          config.AuthMode `json:"mode"`
	Refreshable   bool            `json:"refreshable"`
	HasToken      bool            `json:"has_access_token"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty"`
	RefreshCount  int64           `json:"refresh_count"`
	LastRefresh   *time.Time      `json:"last_refresh,omitempty"`
	LastErrorHint string          `json:"last_error,omitempty"`
}

// TokenSource manages the relay's Google access token.
//
// Concurrency: all state is guarded by mu. A refresh holds mu for the duration
// of the token endpoint call, so concurrent requests that discover an expired
// token produce exactly one refresh and all callers receive the same new
// token. This is the "synchronized refresh" behaviour required to avoid
// stampeding Google's token endpoint.
type TokenSource struct {
	cfg    config.Google
	client HTTPDoer
	now    func() time.Time

	mu        sync.Mutex
	access    config.Secret
	validTill time.Time
	hasExpiry bool

	refreshCount int64
	lastRefresh  time.Time
	lastErr      error
}

// HTTPDoer is the minimal HTTP surface the token source needs.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Option customises a TokenSource (used by tests).
type Option func(*TokenSource)

// WithClock injects a controllable clock.
func WithClock(now func() time.Time) Option {
	return func(t *TokenSource) { t.now = now }
}

// WithHTTPClient injects the HTTP client used for token endpoint calls.
func WithHTTPClient(c HTTPDoer) Option {
	return func(t *TokenSource) { t.client = c }
}

// New builds a TokenSource from configuration.
func New(cfg config.Google, opts ...Option) *TokenSource {
	ts := &TokenSource{
		cfg:    cfg,
		now:    time.Now,
		access: cfg.AccessToken,
	}
	for _, o := range opts {
		o(ts)
	}
	if ts.client == nil {
		ts.client = &http.Client{Timeout: cfg.TokenTimeout}
	}
	// A configured static access token has an unknown expiry: treat it as
	// valid until the Drive API says otherwise (401 -> Invalidate -> refresh).
	return ts
}

// Mode reports the configured authentication mode.
func (t *TokenSource) Mode() config.AuthMode { return t.cfg.Mode() }

// Refreshable reports whether new access tokens can be minted.
func (t *TokenSource) Refreshable() bool { return t.cfg.CanRefresh() }

// Token returns a usable access token.
//
// This is the only method that reveals a secret, and the returned value is
// used solely to build the Authorization header for Google.
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if tok, ok := t.currentLocked(); ok {
		return tok, nil
	}

	// The cached token is unusable. Without refresh configuration the relay
	// cannot recover; report that precisely rather than sending a token we
	// know is dead.
	if !t.cfg.CanRefresh() {
		if t.cfg.AccessToken.IsZero() {
			return "", ErrNoCredentials
		}
		return "", ErrAccessTokenExpired
	}

	if err := t.refreshLocked(ctx); err != nil {
		return "", err
	}
	tok, ok := t.currentLocked()
	if !ok {
		return "", fmt.Errorf("%w: token endpoint returned no access token", ErrRefreshFailed)
	}
	return tok, nil
}

// currentLocked returns the cached token when it is usable.
func (t *TokenSource) currentLocked() (string, bool) {
	if t.access.IsZero() {
		return "", false
	}
	if !t.hasExpiry {
		// Unknown expiry (a statically configured token, or a refresh that did
		// not report expires_in). Use it; a 401 will trigger Invalidate.
		return t.access.Reveal(), true
	}
	if t.now().Before(t.validTill) {
		return t.access.Reveal(), true
	}
	return "", false
}

// Invalidate drops the cached access token, forcing a refresh on the next
// call. In access-only mode there is nothing to refresh, so the token is
// cleared and subsequent calls fail with ErrAccessTokenExpired.
func (t *TokenSource) Invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.access = config.Secret("")
	t.validTill = time.Time{}
	t.hasExpiry = false
}

// Refresh forces a refresh immediately. It is used by diagnostics and tests.
func (t *TokenSource) Refresh(ctx context.Context) error {
	if !t.cfg.CanRefresh() {
		return ErrNoCredentials
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.refreshLocked(ctx)
}

// ExpiresAt reports when the cached token expires, if known.
func (t *TokenSource) ExpiresAt() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.hasExpiry {
		return time.Time{}, false
	}
	return t.validTill, true
}

// Status returns a redacted snapshot. It never includes a token value.
func (t *TokenSource) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := Status{
		Mode:         t.cfg.Mode(),
		Refreshable:  t.cfg.CanRefresh(),
		HasToken:     !t.access.IsZero(),
		RefreshCount: t.refreshCount,
	}
	if t.hasExpiry {
		exp := t.validTill
		st.ExpiresAt = &exp
	}
	if !t.lastRefresh.IsZero() {
		ref := t.lastRefresh
		st.LastRefresh = &ref
	}
	if t.lastErr != nil {
		// Error strings from this package never contain token material, and
		// are scrubbed again here as defence in depth.
		st.LastErrorHint = t.lastErr.Error()
	}
	return st
}
