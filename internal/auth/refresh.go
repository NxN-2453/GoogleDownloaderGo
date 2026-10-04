package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/config"
	"github.com/NxN-2453/GoogleDownloaderGo/internal/logging"
)

// maxTokenResponseBytes bounds how much of a token endpoint response we read,
// so a hostile or broken endpoint cannot exhaust memory.
const maxTokenResponseBytes = 64 * 1024

// tokenResponse mirrors the relevant fields of an OAuth 2.0 token response.
type tokenResponse struct {
	AccessToken      string  `json:"access_token"`
	ExpiresIn        float64 `json:"expires_in"`
	TokenType        string  `json:"token_type"`
	Scope            string  `json:"scope"`
	RefreshToken     string  `json:"refresh_token"`
	Error            string  `json:"error"`
	ErrorDescription string  `json:"error_description"`
	ErrorURI         string  `json:"error_uri"`
}

// refreshLocked performs the refresh_token grant. The caller must hold mu.
//
// Holding the lock across the network call is deliberate: it serialises
// concurrent refreshes so only one request reaches Google and every waiting
// caller observes the same fresh token.
func (t *TokenSource) refreshLocked(ctx context.Context) error {
	if !t.cfg.CanRefresh() {
		err := ErrNoCredentials
		t.lastErr = err
		return err
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.cfg.RefreshToken.Reveal()},
		"client_id":     {t.cfg.ClientID.Reveal()},
		"client_secret": {t.cfg.ClientSecret.Reveal()},
	}

	// A dedicated context bounds the call even if the injected client has no
	// timeout of its own.
	ctx, cancel := context.WithTimeout(ctx, t.cfg.TokenTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.lastErr = fmt.Errorf("%w: %v", ErrRefreshFailed, err)
		return t.lastErr
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Some intermediaries cache POSTs; be explicit.
	req.Header.Set("Cache-Control", "no-store")

	resp, err := t.client.Do(req)
	if err != nil {
		// The error may embed the request URL. The body is never in the URL,
		// and Scrub guards against a client that echoes one. Ensure the token
		// endpoint failure is reported without credential material.
		t.lastErr = fmt.Errorf("%w: %s", ErrRefreshFailed, logging.Scrub(redactURL(err.Error())))
		return t.lastErr
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		t.lastErr = fmt.Errorf("%w: reading response: %v", ErrRefreshFailed, err)
		return t.lastErr
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		// Never echo the raw body: it could contain a token.
		t.lastErr = fmt.Errorf("%w: token endpoint returned a non-JSON response (HTTP %d)", ErrRefreshFailed, resp.StatusCode)
		return t.lastErr
	}

	if resp.StatusCode != http.StatusOK || tr.Error != "" {
		t.lastErr = classifyTokenError(resp.StatusCode, tr)
		return t.lastErr
	}
	if tr.AccessToken == "" {
		t.lastErr = fmt.Errorf("%w: token endpoint returned an empty access token", ErrRefreshFailed)
		return t.lastErr
	}

	t.access = config.Secret(tr.AccessToken)
	t.hasExpiry = true
	t.validTill = t.now().Add(t.validityWindow(tr.ExpiresIn))
	t.refreshCount++
	t.lastRefresh = t.now()
	t.lastErr = nil
	return nil
}

// validityWindow converts expires_in into the local validity window, applying
// the configured proactive-refresh skew.
func (t *TokenSource) validityWindow(expiresIn float64) time.Duration {
	window := time.Duration(expiresIn * float64(time.Second))
	if window <= 0 {
		// Google always sends expires_in; if it is absent assume the
		// documented default of one hour rather than treating the token as
		// instantly stale.
		window = time.Hour
	}
	skew := t.cfg.RefreshSkew
	switch {
	case skew <= 0:
		return window
	case window > skew:
		return window - skew
	default:
		// A token that expires sooner than the skew: refresh at the halfway
		// point instead of never considering it valid.
		return window / 2
	}
}

// classifyTokenError maps a token endpoint failure onto a sentinel error.
//
// The error_description comes from the network, so it is scrubbed and bounded
// before being embedded: a hostile or misconfigured endpoint could otherwise
// echo the submitted refresh token or client secret straight into our logs.
func classifyTokenError(status int, tr tokenResponse) error {
	desc := strings.TrimSpace(logging.Scrub(tr.ErrorDescription))
	if len(desc) > 300 {
		desc = desc[:300] + "..."
	}

	switch tr.Error {
	case "invalid_grant":
		if desc != "" {
			return fmt.Errorf("%w: %s", ErrInvalidGrant, desc)
		}
		return ErrInvalidGrant
	case "invalid_client", "unauthorized_client":
		if desc != "" {
			return fmt.Errorf("%w: %s", ErrInvalidClient, desc)
		}
		return ErrInvalidClient
	case "invalid_request":
		return fmt.Errorf("%w: invalid_request: %s", ErrRefreshFailed, desc)
	case "":
		return fmt.Errorf("%w: token endpoint returned HTTP %d", ErrRefreshFailed, status)
	default:
		if desc != "" {
			return fmt.Errorf("%w: %s: %s", ErrRefreshFailed, tr.Error, desc)
		}
		return fmt.Errorf("%w: %s", ErrRefreshFailed, tr.Error)
	}
}

// redactURL strips anything that looks like a URL from an error string so a
// transport error cannot smuggle a token endpoint URL (which is not secret)
// or, more importantly, a proxy URL containing credentials into a log.
func redactURL(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[:i] + "://[REDACTED]"
	}
	return s
}

// IsAuthError reports whether err indicates a credential problem rather than
// a transient failure. Handlers use it to choose 401 over 502.
func IsAuthError(err error) bool {
	return errors.Is(err, ErrNoCredentials) ||
		errors.Is(err, ErrAccessTokenExpired) ||
		errors.Is(err, ErrInvalidGrant) ||
		errors.Is(err, ErrInvalidClient)
}
