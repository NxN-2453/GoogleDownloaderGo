package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/config"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// tokenServer is a controllable stand-in for Google's token endpoint.
type tokenServer struct {
	mu       sync.Mutex
	requests []map[string]string
	calls    int32
	// handler lets a test override the response.
	handler func(w http.ResponseWriter, r *http.Request)
}

func newTokenServer(t *testing.T) (*tokenServer, *httptest.Server) {
	t.Helper()
	ts := &tokenServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		atomic.AddInt32(&ts.calls, 1)
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		ts.mu.Lock()
		ts.requests = append(ts.requests, form)
		h := ts.handler
		ts.mu.Unlock()

		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"refreshed-token-%d","expires_in":3600,"token_type":"Bearer"}`, atomic.LoadInt32(&ts.calls))
	}))
	t.Cleanup(srv.Close)
	return ts, srv
}

func (ts *tokenServer) setHandler(h func(w http.ResponseWriter, r *http.Request)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.handler = h
}

func (ts *tokenServer) callCount() int { return int(atomic.LoadInt32(&ts.calls)) }

func (ts *tokenServer) firstRequest(t *testing.T) map[string]string {
	t.Helper()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.requests) == 0 {
		t.Fatal("token endpoint was never called")
	}
	return ts.requests[0]
}

func refreshConfig(endpoint string) config.Google {
	return config.Google{
		AccessToken:   config.Secret("initial-access-token"),
		RefreshToken:  config.Secret("1//refresh-token-value"),
		ClientID:      config.Secret("client-id.apps.googleusercontent.com"),
		ClientSecret:  config.Secret("GOCSPX-secret-value"),
		TokenEndpoint: endpoint,
		RefreshSkew:   2 * time.Minute,
		TokenTimeout:  5 * time.Second,
	}
}

func TestAccessOnlyModeReturnsStaticToken(t *testing.T) {
	cfg := config.Google{
		AccessToken:   config.Secret("static-token"),
		TokenEndpoint: config.DefaultTokenEndpoint,
		TokenTimeout:  time.Second,
	}
	ts := New(cfg, WithClock(newFakeClock().Now))

	if ts.Mode() != config.AuthModeAccessOnly {
		t.Fatalf("Mode() = %q, want access-only", ts.Mode())
	}
	if ts.Refreshable() {
		t.Fatal("access-only mode must not be refreshable")
	}
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if got != "static-token" {
		t.Fatalf("Token() = %q, want static-token", got)
	}
}

func TestNoCredentials(t *testing.T) {
	ts := New(config.Google{TokenEndpoint: config.DefaultTokenEndpoint, TokenTimeout: time.Second})
	if ts.Mode() != config.AuthModeNone {
		t.Fatalf("Mode() = %q, want none", ts.Mode())
	}
	_, err := ts.Token(context.Background())
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("Token() error = %v, want ErrNoCredentials", err)
	}
}

func TestExpiredAccessOnlyTokenReportsClearError(t *testing.T) {
	clock := newFakeClock()
	ts := New(config.Google{
		AccessToken:   config.Secret("static-token"),
		TokenEndpoint: config.DefaultTokenEndpoint,
		TokenTimeout:  time.Second,
	}, WithClock(clock.Now))

	// Simulate the Drive API rejecting the token.
	ts.Invalidate()

	_, err := ts.Token(context.Background())
	if !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("Token() error = %v, want ErrAccessTokenExpired", err)
	}
	if !IsAuthError(err) {
		t.Fatal("expired access token must classify as an auth error")
	}
}

func TestRefreshModeFetchesTokenWhenAccessTokenMissing(t *testing.T) {
	_, srv := newTokenServer(t)
	clock := newFakeClock()

	cfg := refreshConfig(srv.URL)
	cfg.AccessToken = config.Secret("") // refresh-only bootstrapping
	ts := New(cfg, WithClock(clock.Now))

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if !strings.HasPrefix(tok, "refreshed-token-") {
		t.Fatalf("Token() = %q, want a refreshed token", tok)
	}
}

func TestRefreshSendsCorrectGrant(t *testing.T) {
	tsSrv, srv := newTokenServer(t)
	clock := newFakeClock()
	ts := New(refreshConfig(srv.URL), WithClock(clock.Now))

	// Force a refresh by expiring the initial token.
	ts.Invalidate()
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	req := tsSrv.firstRequest(t)
	if got := req["grant_type"]; got != "refresh_token" {
		t.Fatalf("grant_type = %q, want refresh_token", got)
	}
	if got := req["refresh_token"]; got != "1//refresh-token-value" {
		t.Fatalf("refresh_token = %q, want the configured value", got)
	}
	if got := req["client_id"]; got != "client-id.apps.googleusercontent.com" {
		t.Fatalf("client_id = %q", got)
	}
	if got := req["client_secret"]; got != "GOCSPX-secret-value" {
		t.Fatalf("client_secret = %q", got)
	}
}

func TestProactiveRefreshBeforeExpiry(t *testing.T) {
	tsSrv, srv := newTokenServer(t)
	clock := newFakeClock()
	ts := New(refreshConfig(srv.URL), WithClock(clock.Now))

	// Token is valid for 3600s minus the 120s skew = 3480s.
	ts.Invalidate()
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("initial Token() error: %v", err)
	}
	before := tsSrv.callCount()

	// Still inside the validity window: no new call.
	clock.Advance(30 * time.Minute)
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if got := tsSrv.callCount(); got != before {
		t.Fatalf("token endpoint called %d times, want %d (cached token should be reused)", got, before)
	}

	// Cross into the skew window: refresh must happen before real expiry.
	clock.Advance(30 * time.Minute) // total 60m, expiry at 58m
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if got := tsSrv.callCount(); got != before+1 {
		t.Fatalf("token endpoint called %d times, want %d (proactive refresh expected)", got, before+1)
	}
}

func TestSynchronizedRefreshUnderConcurrency(t *testing.T) {
	tsSrv, srv := newTokenServer(t)
	clock := newFakeClock()

	// Make the endpoint slow so concurrent callers pile up on the lock.
	release := make(chan struct{})
	tsSrv.setHandler(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"concurrent-token","expires_in":3600}`)
	})

	cfg := refreshConfig(srv.URL)
	cfg.AccessToken = config.Secret("")
	ts := New(cfg, WithClock(clock.Now))

	const goroutines = 50
	var wg sync.WaitGroup
	var failures int32
	results := make([]string, goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			tok, err := ts.Token(context.Background())
			if err != nil {
				atomic.AddInt32(&failures, 1)
				return
			}
			results[idx] = tok
		}(i)
	}
	close(start)
	// Give the goroutines a moment to contend, then let the request complete.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if failures != 0 {
		t.Fatalf("%d goroutines failed to obtain a token", failures)
	}
	if got := tsSrv.callCount(); got != 1 {
		t.Fatalf("token endpoint called %d times, want exactly 1 (synchronized refresh)", got)
	}
	for i, r := range results {
		if r != "concurrent-token" {
			t.Fatalf("goroutine %d received %q, want concurrent-token", i, r)
		}
	}
}

func TestRefreshFailureClassification(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    error
		wantAuthEr bool
	}{
		{
			name:       "invalid grant",
			status:     http.StatusBadRequest,
			body:       `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`,
			wantErr:    ErrInvalidGrant,
			wantAuthEr: true,
		},
		{
			name:       "invalid client",
			status:     http.StatusUnauthorized,
			body:       `{"error":"invalid_client","error_description":"Unauthorized"}`,
			wantErr:    ErrInvalidClient,
			wantAuthEr: true,
		},
		{
			name:    "server error",
			status:  http.StatusInternalServerError,
			body:    `{"error":"internal_failure"}`,
			wantErr: ErrRefreshFailed,
		},
		{
			name:    "empty error body",
			status:  http.StatusBadGateway,
			body:    ``,
			wantErr: ErrRefreshFailed,
		},
		{
			name:    "no access token in response",
			status:  http.StatusOK,
			body:    `{"expires_in":3600}`,
			wantErr: ErrRefreshFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tsSrv, srv := newTokenServer(t)
			tsSrv.setHandler(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})

			cfg := refreshConfig(srv.URL)
			cfg.AccessToken = config.Secret("")
			ts := New(cfg, WithClock(newFakeClock().Now))

			_, err := ts.Token(context.Background())
			if err == nil {
				t.Fatalf("Token() succeeded, want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Token() error = %v, want %v", err, tc.wantErr)
			}
			if got := IsAuthError(err); got != tc.wantAuthEr {
				t.Fatalf("IsAuthError(%v) = %v, want %v", err, got, tc.wantAuthEr)
			}
			// The failure must not leave a usable token behind.
			if _, err := ts.Token(context.Background()); err == nil {
				t.Fatal("Token() succeeded after a refresh failure")
			}
		})
	}
}

func TestRefreshFailureNeverLeaksCredentials(t *testing.T) {
	// A hostile endpoint echoes the submitted credentials back in the error
	// description. Nothing secret may reach the returned error.
	tsSrv, srv := newTokenServer(t)
	tsSrv.setHandler(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"refresh_token=%s client_secret=%s"}`,
			r.PostForm.Get("refresh_token"), r.PostForm.Get("client_secret"))
	})

	cfg := refreshConfig(srv.URL)
	cfg.AccessToken = config.Secret("")
	ts := New(cfg, WithClock(newFakeClock().Now))

	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, secret := range []string{"1//refresh-token-value", "GOCSPX-secret-value"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error message leaked a credential: %q", msg)
		}
	}
}

func TestTokenEndpointTransportErrorIsScrubbed(t *testing.T) {
	cfg := refreshConfig("https://oauth2.googleapis.com/token")
	cfg.AccessToken = config.Secret("")
	doer := errDoer{err: errors.New("Post \"https://user:hunter2@proxy.internal/token\": dial tcp: refused")}
	ts := New(cfg, WithHTTPClient(doer))

	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrRefreshFailed) {
		t.Fatalf("error = %v, want ErrRefreshFailed", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("transport error leaked credentials: %q", err.Error())
	}
}

type errDoer struct{ err error }

func (d errDoer) Do(*http.Request) (*http.Response, error) { return nil, d.err }

func TestInvalidateForcesRefreshInRefreshMode(t *testing.T) {
	tsSrv, srv := newTokenServer(t)
	ts := New(refreshConfig(srv.URL), WithClock(newFakeClock().Now))

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if tsSrv.callCount() != 0 {
		t.Fatal("a valid static token should not trigger a refresh")
	}

	ts.Invalidate()
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token() after Invalidate error: %v", err)
	}
	if tsSrv.callCount() != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", tsSrv.callCount())
	}
}

func TestStatusIsRedacted(t *testing.T) {
	_, srv := newTokenServer(t)
	ts := New(refreshConfig(srv.URL), WithClock(newFakeClock().Now))
	ts.Invalidate()
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	st := ts.Status()
	if st.Mode != config.AuthModeRefresh || !st.Refreshable || !st.HasToken {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.RefreshCount != 1 {
		t.Fatalf("RefreshCount = %d, want 1", st.RefreshCount)
	}
	if st.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil, want a timestamp")
	}

	rendered := fmt.Sprintf("%+v", st)
	for _, secret := range []string{"1//refresh-token-value", "GOCSPX-secret-value", "refreshed-token-1"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("status leaked a credential: %q", rendered)
		}
	}
}

func TestSecretTypeRedaction(t *testing.T) {
	s := config.Secret("super-secret-value")
	if s.String() != "[REDACTED]" {
		t.Fatalf("String() = %q", s.String())
	}
	if fmt.Sprintf("%v", s) != "[REDACTED]" {
		t.Fatalf("formatting leaked: %q", fmt.Sprintf("%v", s))
	}
	if fmt.Sprintf("%#v", s) != "[REDACTED]" {
		t.Fatalf("%%#v leaked: %q", fmt.Sprintf("%#v", s))
	}
	if s.Reveal() != "super-secret-value" {
		t.Fatal("Reveal() did not return the value")
	}
	if config.Secret("").String() != "" {
		t.Fatal("empty secret should render as empty")
	}
}
