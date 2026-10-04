package drive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/auth"
	"github.com/NxN-2453/GoogleDownloaderGo/internal/logging"
	"github.com/NxN-2453/GoogleDownloaderGo/internal/version"
)

// Defaults for the Google Drive API endpoints.
const (
	// DefaultBaseURL is the Drive v3 REST endpoint.
	DefaultBaseURL = "https://www.googleapis.com/drive/v3"

	// DefaultUploadBaseURL is only used as an escape hatch for tests.
	DefaultUploadBaseURL = "https://www.googleapis.com/upload/drive/v3"

	// maxErrorBodyBytes bounds how much of an error response we buffer.
	maxErrorBodyBytes = 64 * 1024

	// maxMetadataBodyBytes bounds a metadata response. Metadata is small; a
	// huge body would indicate a misconfigured base URL.
	maxMetadataBodyBytes = 1024 * 1024
)

// ErrNotConfigured indicates the relay has no usable Google credentials.
var ErrNotConfigured = errors.New("Google Drive is not configured")

// APIError is a structured failure from the Drive API.
type APIError struct {
	// Op is the relay operation that failed, e.g. "files.get".
	Op string
	// StatusCode is the HTTP status returned by Google.
	StatusCode int
	// Reason is Google's machine-readable reason, e.g. "notFound",
	// "userRateLimitExceeded", "cannotDownloadAbusiveFile".
	Reason string
	// Message is Google's human-readable message, scrubbed.
	Message string
}

func (e *APIError) Error() string {
	if e.Reason != "" && e.Message != "" {
		return fmt.Sprintf("drive %s: HTTP %d (%s): %s", e.Op, e.StatusCode, e.Reason, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("drive %s: HTTP %d: %s", e.Op, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("drive %s: HTTP %d", e.Op, e.StatusCode)
}

// IsNotFound reports whether the file or resource is missing.
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound || e.Reason == "notFound"
}

// IsUnauthorized reports an authentication failure (bad or expired token).
func (e *APIError) IsUnauthorized() bool { return e.StatusCode == http.StatusUnauthorized }

// IsForbidden reports a permission or abuse failure.
func (e *APIError) IsForbidden() bool { return e.StatusCode == http.StatusForbidden }

// IsRateLimited reports that Google asked us to slow down.
func (e *APIError) IsRateLimited() bool {
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	switch e.Reason {
	case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "dailyLimitExceeded":
		return true
	}
	return false
}

// IsPermissionDenied reports that the configured account may not read the file.
func (e *APIError) IsPermissionDenied() bool {
	if e.StatusCode == http.StatusForbidden && !e.IsRateLimited() {
		return true
	}
	return e.Reason == "forbidden" || e.Reason == "insufficientFilePermissions" || e.Reason == "appNotAuthorizedToFile"
}

// IsUpstream reports a Google-side failure rather than a client mistake.
func (e *APIError) IsUpstream() bool { return e.StatusCode >= 500 }

// IsAbusive reports a file Google has flagged and refuses to serve.
func (e *APIError) IsAbusive() bool {
	switch e.Reason {
	case "cannotDownloadAbusiveFile", "abusiveContentRestriction", "fileNotDownloadable":
		return true
	}
	return false
}

// AsAPIError extracts an *APIError from err.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// Options configures a Client. Zero values fall back to sensible defaults.
type Options struct {
	BaseURL         string
	UploadBaseURL   string
	HTTPClient      *http.Client
	Tokens          auth.TokenProvider
	Logger          *slogAdapter
	MaxRetriesOn401 int
}

// Client is a minimal, streaming-friendly Google Drive API client.
//
// It implements only what the relay needs (metadata lookup and media
// download), uses the standard library exclusively, and never stores tokens
// itself: every request asks the auth.TokenProvider for a token.
type Client struct {
	baseURL     string
	uploadURL   string
	httpClient  *http.Client
	tokens      auth.TokenProvider
	logger      *slogAdapter
	max401Retry int

	// stats
	apiCalls  int64
	refreshes int64
}

// New creates a Drive client.
func New(opts Options) *Client {
	c := &Client{
		baseURL:     strings.TrimRight(opts.BaseURL, "/"),
		uploadURL:   strings.TrimRight(opts.UploadBaseURL, "/"),
		httpClient:  opts.HTTPClient,
		tokens:      opts.Tokens,
		logger:      opts.Logger,
		max401Retry: opts.MaxRetriesOn401,
	}
	if c.baseURL == "" {
		c.baseURL = DefaultBaseURL
	}
	if c.uploadURL == "" {
		c.uploadURL = DefaultUploadBaseURL
	}
	if c.httpClient == nil {
		// No overall timeout: media downloads are long lived and are bounded
		// by the request context instead. The transport still bounds
		// connection setup.
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		}
	}
	if c.max401Retry == 0 {
		c.max401Retry = 1
	}
	return c
}

// Stats reports lightweight counters for /health.
func (c *Client) Stats() (apiCalls, refreshes int64) {
	return atomic.LoadInt64(&c.apiCalls), atomic.LoadInt64(&c.refreshes)
}

// request describes one Drive API call.
type request struct {
	op      string
	method  string
	rawURL  string
	query   url.Values
	accept  string
	headers map[string]string
	// noRetry disables the 401 retry, used for media requests where the body
	// may already be in flight.
	noRetry bool
}

// do performs an authenticated request, retrying once after a 401 by asking
// the token provider for a fresh token.
//
// Retrying is safe because every call the relay makes is idempotent: a
// metadata GET and a media GET. The response body is returned to the caller,
// who must close it.
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	attempts := 1
	if !r.noRetry {
		attempts += c.max401Retry
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if c.tokens == nil {
			return nil, ErrNotConfigured
		}
		token, err := c.tokens.Token(ctx)
		if err != nil {
			return nil, err
		}

		resp, err := c.send(ctx, r, token)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt < attempts-1 {
			// The token was rejected. Drop it, force a refresh and retry the
			// original request exactly once.
			drain(resp.Body)
			atomic.AddInt64(&c.refreshes, 1)
			c.tokens.Invalidate()
			lastErr = &APIError{Op: r.op, StatusCode: http.StatusUnauthorized, Reason: "unauthorized", Message: "access token rejected by Google"}
			if c.logger != nil {
				c.logger.Debug("drive request returned 401, refreshing token and retrying once", "op", r.op)
			}
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// send performs a single HTTP attempt.
func (c *Client) send(ctx context.Context, r request, token string) (*http.Response, error) {
	u, err := url.Parse(r.rawURL)
	if err != nil {
		return nil, fmt.Errorf("drive %s: invalid URL: %w", r.op, err)
	}
	if len(r.query) > 0 {
		q := u.Query()
		for k, vs := range r.query {
			for _, v := range vs {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("drive %s: build request: %w", r.op, err)
	}
	// The token is placed only in this header. It never appears in a URL, a
	// log line, or a response.
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.UserAgent)
	if r.accept != "" {
		req.Header.Set("Accept", r.accept)
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}

	atomic.AddInt64(&c.apiCalls, 1)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transport errors can embed the URL (which holds only a file ID) and
		// occasionally proxy credentials. Scrub before surfacing.
		return nil, fmt.Errorf("drive %s: %s", r.op, logging.Scrub(err.Error()))
	}
	return resp, nil
}

// decodeError converts a non-2xx Drive response into an *APIError.
func (c *Client) decodeError(op string, resp *http.Response) *APIError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	drain(resp.Body)

	apiErr := &APIError{Op: op, StatusCode: resp.StatusCode}

	var envelope struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
			Errors  []struct {
				Domain  string `json:"domain"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"errors"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Error.Message != "" {
		apiErr.Message = logging.Scrub(envelope.Error.Message)
		if len(envelope.Error.Errors) > 0 {
			apiErr.Reason = envelope.Error.Errors[0].Reason
			if apiErr.Reason == "" {
				apiErr.Reason = envelope.Error.Errors[0].Domain
			}
		} else if envelope.Error.Status != "" {
			apiErr.Reason = envelope.Error.Status
		}
	} else {
		// Not JSON (Google sometimes returns text/plain for media errors).
		// Keep a short, scrubbed snippet for diagnostics but never the whole
		// body.
		snippet := logging.Scrub(strings.TrimSpace(string(body)))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		apiErr.Message = snippet
	}

	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	return apiErr
}

func drain(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}

// slogAdapter is a tiny indirection so the drive package does not depend on a
// concrete logger implementation. It mirrors the subset of slog we use.
type slogAdapter struct {
	debug func(msg string, args ...any)
	warn  func(msg string, args ...any)
}

// NewLogger wires a debug/warn logger pair.
func NewLogger(debug, warn func(msg string, args ...any)) *slogAdapter {
	return &slogAdapter{debug: debug, warn: warn}
}

func (l *slogAdapter) Debug(msg string, args ...any) {
	if l != nil && l.debug != nil {
		l.debug(msg, args...)
	}
}

func (l *slogAdapter) Warn(msg string, args ...any) {
	if l != nil && l.warn != nil {
		l.warn(msg, args...)
	}
}
