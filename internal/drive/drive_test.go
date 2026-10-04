package drive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/auth"
	"github.com/NxN-2453/GoogleDownloaderGo/internal/utils"
)

// fakeTokens is a controllable TokenProvider.
type fakeTokens struct {
	mu           sync.Mutex
	token        string
	invalidated  int
	err          error
	nextAfterInv string
}

func (f *fakeTokens) Token(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

func (f *fakeTokens) Invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated++
	if f.nextAfterInv != "" {
		f.token = f.nextAfterInv
	}
}

func (f *fakeTokens) invalidations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.invalidated
}

// fakeDrive serves canned metadata and media responses.
type fakeDrive struct {
	mu        sync.Mutex
	metadata  map[string]string // id -> JSON body
	media     map[string][]byte // id -> bytes
	statuses  map[string]int    // id -> forced status for metadata
	authSeen  []string          // Authorization headers observed
	rangeSeen []string          // Range headers observed
	requests  int32
}

func newFakeDrive() *fakeDrive {
	return &fakeDrive{
		metadata: map[string]string{},
		media:    map[string][]byte{},
		statuses: map[string]int{},
	}
}

func (f *fakeDrive) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.requests, 1)
		f.mu.Lock()
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		if rng := r.Header.Get("Range"); rng != "" {
			f.rangeSeen = append(f.rangeSeen, rng)
		}
		f.mu.Unlock()

		// Path shape: /files/{id}
		path := strings.TrimPrefix(r.URL.Path, "/files/")
		id := path
		isMedia := r.URL.Query().Get("alt") == "media"

		f.mu.Lock()
		forced := f.statuses[id]
		body, hasMeta := f.metadata[id]
		content, hasMedia := f.media[id]
		f.mu.Unlock()

		if forced != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(forced)
			fmt.Fprintf(w, `{"error":{"code":%d,"message":"forced %d","errors":[{"reason":"forced"}]}}`, forced, forced)
			return
		}

		if isMedia {
			if !hasMedia {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":{"code":404,"message":"File not found","errors":[{"reason":"notFound"}]}}`)
				return
			}
			serveBytes(w, r, content)
			return
		}

		if !hasMeta {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":404,"message":"File not found: x","errors":[{"reason":"notFound","domain":"drive"}]}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serveBytes implements enough Range support to exercise the relay.
func serveBytes(w http.ResponseWriter, r *http.Request, content []byte) {
	w.Header().Set("Accept-Ranges", "bytes")
	rng := r.Header.Get("Range")
	if rng == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
		return
	}
	parsed, err := utils.ParseRange(rng, int64(len(content)))
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(content)))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Range", parsed.ContentRange(int64(len(content))))
	w.Header().Set("Content-Length", fmt.Sprint(parsed.Length))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(content[parsed.Start : parsed.End+1])
}

func (f *fakeDrive) lastAuth() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.authSeen) == 0 {
		return ""
	}
	return f.authSeen[len(f.authSeen)-1]
}

func newTestClient(t *testing.T, fd *fakeDrive, tokens auth.TokenProvider) *Client {
	t.Helper()
	srv := fd.serve(t)
	return New(Options{
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
		Tokens:     tokens,
	})
}

const testID = "1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW"

func TestGetFileMetadata(t *testing.T) {
	fd := newFakeDrive()
	fd.metadata[testID] = `{
		"id":"` + testID + `",
		"name":"sample.txt",
		"mimeType":"text/plain",
		"size":"1234",
		"md5Checksum":"d41d8cd98f00b204e9800998ecf8427e",
		"modifiedTime":"2026-01-02T03:04:05.000Z",
		"driveId":"0ABCDEF",
		"webViewLink":"https://drive.google.com/file/d/` + testID + `/view",
		"capabilities":{"canDownload":true},
		"owners":[{"emailAddress":"owner@example.com"}]
	}`

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	got, err := c.GetFile(context.Background(), testID)
	if err != nil {
		t.Fatalf("GetFile() error: %v", err)
	}

	if got.ID != testID {
		t.Errorf("ID = %q", got.ID)
	}
	if got.Name != "sample.txt" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.MimeType != "text/plain" {
		t.Errorf("MimeType = %q", got.MimeType)
	}
	if got.Size != 1234 || !got.SizeKnown {
		t.Errorf("Size = %d known=%v, want 1234 true", got.Size, got.SizeKnown)
	}
	if got.DriveID != "0ABCDEF" {
		t.Errorf("DriveID = %q (shared drive support)", got.DriveID)

	}
	if !got.CanDownload {
		t.Error("CanDownload = false, want true")
	}
	if got.Owner != "owner@example.com" {
		t.Errorf("Owner = %q", got.Owner)
	}
	if got.IsGoogleWorkspace || got.IsFolder || got.Trashed {
		t.Errorf("unexpected flags: workspace=%v folder=%v trashed=%v", got.IsGoogleWorkspace, got.IsFolder, got.Trashed)
	}
	if err := CheckDownloadable(got); err != nil {
		t.Errorf("CheckDownloadable() = %v, want nil", err)
	}
	if fd.lastAuth() != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", fd.lastAuth())
	}
}

func TestGetFileSizeUnknownWhenAbsent(t *testing.T) {
	fd := newFakeDrive()
	fd.metadata[testID] = `{"id":"` + testID + `","name":"mystery.bin","mimeType":"application/octet-stream","capabilities":{"canDownload":true}}`

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	got, err := c.GetFile(context.Background(), testID)
	if err != nil {
		t.Fatalf("GetFile() error: %v", err)
	}
	if got.SizeKnown {
		t.Fatal("SizeKnown = true, want false when Drive omits size")
	}
}

func TestGetFileRejectsInvalidIDBeforeAnyRequest(t *testing.T) {
	fd := newFakeDrive()
	c := newTestClient(t, fd, &fakeTokens{token: "tok"})

	if _, err := c.GetFile(context.Background(), "bad id!"); err == nil {
		t.Fatal("expected an error for an invalid file ID")
	}
	if n := atomic.LoadInt32(&fd.requests); n != 0 {
		t.Fatalf("made %d requests for an invalid ID, want 0", n)
	}
}

func TestGetFileWorkspaceDetection(t *testing.T) {
	fd := newFakeDrive()
	fd.metadata[testID] = `{"id":"` + testID + `","name":"My Doc","mimeType":"application/vnd.google-apps.document","capabilities":{"canDownload":true}}`

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	got, err := c.GetFile(context.Background(), testID)
	if err != nil {
		t.Fatalf("GetFile() error: %v", err)
	}
	if !got.IsGoogleWorkspace {
		t.Fatal("IsGoogleWorkspace = false, want true")
	}
	if got.SizeKnown {
		t.Fatal("a Workspace document must not report a known byte size")
	}
	err = CheckDownloadable(got)
	if !errors.Is(err, ErrWorkspaceFile) {
		t.Fatalf("CheckDownloadable() = %v, want ErrWorkspaceFile", err)
	}
	if got.ExportSuggestion == nil || got.ExportSuggestion.MimeType != "application/pdf" {
		t.Fatalf("ExportSuggestion = %+v, want a PDF suggestion", got.ExportSuggestion)
	}
}

func TestGetFileFolderAndTrashedRejected(t *testing.T) {
	fd := newFakeDrive()
	fd.metadata["folder1"] = `{"id":"folder1","name":"My Folder","mimeType":"application/vnd.google-apps.folder"}`
	fd.metadata["trash1"] = `{"id":"trash1","name":"Old.txt","mimeType":"text/plain","size":"10","trashed":true,"capabilities":{"canDownload":true}}`
	fd.metadata["nodl1"] = `{"id":"nodl1","name":"Secret.txt","mimeType":"text/plain","size":"10","capabilities":{"canDownload":false}}`

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})

	folder, err := c.GetFile(context.Background(), "folder1")
	if err != nil {
		t.Fatalf("GetFile(folder) error: %v", err)
	}
	if !folder.IsFolder {
		t.Error("IsFolder = false, want true")
	}
	if err := CheckDownloadable(folder); !errors.Is(err, ErrNotDownloadable) {
		t.Errorf("folder CheckDownloadable() = %v, want ErrNotDownloadable", err)
	}

	trashed, err := c.GetFile(context.Background(), "trash1")
	if err != nil {
		t.Fatalf("GetFile(trashed) error: %v", err)
	}
	if !trashed.Trashed {
		t.Error("Trashed = false, want true")
	}
	if err := CheckDownloadable(trashed); !errors.Is(err, ErrNotDownloadable) {
		t.Errorf("trashed CheckDownloadable() = %v, want ErrNotDownloadable", err)
	}

	nodl, err := c.GetFile(context.Background(), "nodl1")
	if err != nil {
		t.Fatalf("GetFile(nodl) error: %v", err)
	}
	if nodl.CanDownload {
		t.Error("CanDownload = true, want false")
	}
	if err := CheckDownloadable(nodl); !errors.Is(err, ErrNotDownloadable) {
		t.Errorf("no-download CheckDownloadable() = %v, want ErrNotDownloadable", err)
	}
}

func TestGetFileResolvesShortcut(t *testing.T) {
	const target = "targetFileId123456789012345678"
	fd := newFakeDrive()
	fd.metadata["shortcut1"] = `{"id":"shortcut1","name":"link","mimeType":"application/vnd.google-apps.shortcut","shortcutDetails":{"targetId":"` + target + `","targetMimeType":"text/plain"}}`
	fd.metadata[target] = `{"id":"` + target + `","name":"real.txt","mimeType":"text/plain","size":"42","capabilities":{"canDownload":true}}`

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	got, err := c.GetFile(context.Background(), "shortcut1")
	if err != nil {
		t.Fatalf("GetFile(shortcut) error: %v", err)
	}
	if got.ID != target {
		t.Fatalf("ID = %q, want the shortcut target %q", got.ID, target)
	}
	if got.Name != "real.txt" || got.Size != 42 {
		t.Fatalf("resolved file = %+v", got)
	}
	if got.Raw["shortcut_id"] != "shortcut1" {
		t.Fatalf("shortcut_id not preserved in Raw: %v", got.Raw["shortcut_id"])
	}
}

func TestGetFileShortcutLoopTerminates(t *testing.T) {
	fd := newFakeDrive()
	// A shortcut that points at itself.
	fd.metadata["loop1"] = `{"id":"loop1","name":"loop","mimeType":"application/vnd.google-apps.shortcut","shortcutDetails":{"targetId":"loop1","targetMimeType":"text/plain"}}`

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	_, err := c.GetFile(context.Background(), "loop1")
	if !errors.Is(err, ErrShortcutLoop) {
		t.Fatalf("GetFile(loop) = %v, want ErrShortcutLoop", err)
	}
}

func TestAPIErrorClassification(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		check      func(*APIError) bool
		wantReason string
	}{
		{"not found", 404, `{"error":{"code":404,"message":"File not found",	"errors":[{"reason":"notFound"}]}}`, (*APIError).IsNotFound, "notFound"},
		{"permission denied", 403, `{"error":{"code":403,"message":"The user does not have sufficient permissions","errors":[{"reason":"insufficientFilePermissions"}]}}`, (*APIError).IsPermissionDenied, "insufficientFilePermissions"},
		{"rate limited", 429, `{"error":{"code":429,"message":"Rate limit exceeded","errors":[{"reason":"userRateLimitExceeded"}]}}`, (*APIError).IsRateLimited, "userRateLimitExceeded"},
		{"quota", 403, `{"error":{"code":403,"message":"Quota exceeded","errors":[{"reason":"quotaExceeded"}]}}`, (*APIError).IsRateLimited, "quotaExceeded"},
		{"abusive", 403, `{"error":{"code":403,"message":"Abusive content","errors":[{"reason":"cannotDownloadAbusiveFile"}]}}`, (*APIError).IsAbusive, "cannotDownloadAbusiveFile"},
		{"server error", 500, `{"error":{"code":500,"message":"Backend Error","errors":[{"reason":"backendError"}]}}`, (*APIError).IsUpstream, "backendError"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fd := newFakeDrive()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(srv.Close)

			c := New(Options{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: &fakeTokens{token: "tok"}})
			_ = fd

			_, err := c.GetFile(context.Background(), testID)
			if err == nil {
				t.Fatal("expected an error")
			}
			apiErr, ok := AsAPIError(err)
			if !ok {
				t.Fatalf("error is not an *APIError: %v", err)
			}
			if apiErr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tc.status)
			}
			if apiErr.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", apiErr.Reason, tc.wantReason)
			}
			if !tc.check(apiErr) {
				t.Errorf("classification predicate failed for %+v", apiErr)
			}
		})
	}
}

func TestUnauthorizedTriggersSingleRefreshAndRetry(t *testing.T) {
	var calls int32
	var seen []string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()

		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":401,"message":"Invalid Credentials","errors":[{"reason":"authError"}]}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"name":"ok.txt","mimeType":"text/plain","size":"5","capabilities":{"canDownload":true}}`, testID)
	}))
	t.Cleanup(srv.Close)

	tokens := &fakeTokens{token: "stale-token", nextAfterInv: "fresh-token"}
	c := New(Options{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: tokens})

	got, err := c.GetFile(context.Background(), testID)
	if err != nil {
		t.Fatalf("GetFile() error after refresh: %v", err)
	}
	if got.Name != "ok.txt" {
		t.Fatalf("Name = %q", got.Name)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("upstream calls = %d, want exactly 2 (original + one retry)", n)
	}
	if tokens.invalidations() != 1 {
		t.Fatalf("Invalidate called %d times, want 1", tokens.invalidations())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "Bearer stale-token" || seen[1] != "Bearer fresh-token" {
		t.Fatalf("authorization sequence = %v, want [Bearer stale-token, Bearer fresh-token]", seen)
	}
}

func TestUnauthorizedGivesUpAfterOneRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":401,"message":"Invalid Credentials","errors":[{"reason":"authError"}]}}`)
	}))
	t.Cleanup(srv.Close)

	tokens := &fakeTokens{token: "stale"}
	c := New(Options{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: tokens})

	_, err := c.GetFile(context.Background(), testID)
	if err == nil {
		t.Fatal("expected an error")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("upstream calls = %d, want 2 (no infinite retry loop)", n)
	}
	apiErr, ok := AsAPIError(err)
	if !ok || !apiErr.IsUnauthorized() {
		t.Fatalf("error = %v, want an unauthorized APIError", err)
	}
}

func TestTokenProviderErrorIsSurfaced(t *testing.T) {
	fd := newFakeDrive()
	sentinel := errors.New("boom")
	c := newTestClient(t, fd, &fakeTokens{err: sentinel})

	_, err := c.GetFile(context.Background(), testID)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the token provider error", err)
	}
	if n := atomic.LoadInt32(&fd.requests); n != 0 {
		t.Fatalf("made %d upstream requests without a token, want 0", n)
	}
}

func TestNilTokenProviderReportsNotConfigured(t *testing.T) {
	fd := newFakeDrive()
	srv := fd.serve(t)
	c := New(Options{BaseURL: srv.URL, HTTPClient: srv.Client()})

	_, err := c.GetFile(context.Background(), testID)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
}

// ---------------------------------------------------------------------------
// Media streaming
// ---------------------------------------------------------------------------

func mediaFile(id string, size int64) *File {
	return &File{ID: id, Name: "sample.bin", MimeType: "application/octet-stream", Size: size, SizeKnown: true, CanDownload: true}
}

func TestOpenMediaFullStream(t *testing.T) {
	content := []byte("0123456789abcdefghij")
	fd := newFakeDrive()
	fd.media["file1"] = content

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	ms, err := c.OpenMedia(context.Background(), mediaFile("file1", int64(len(content))), nil)
	if err != nil {
		t.Fatalf("OpenMedia() error: %v", err)
	}
	defer ms.Body.Close()

	if ms.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", ms.StatusCode)
	}
	if ms.ContentLength != int64(len(content)) {
		t.Fatalf("ContentLength = %d, want %d", ms.ContentLength, len(content))
	}
	got, err := io.ReadAll(ms.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("body = %q, want %q", got, content)
	}
}

func TestOpenMediaWithRangeSendsUpstreamRange(t *testing.T) {
	content := []byte("0123456789abcdefghij")
	fd := newFakeDrive()
	fd.media["file1"] = content

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	rng := &utils.ByteRange{Start: 5, End: 9, Length: 5}
	ms, err := c.OpenMedia(context.Background(), mediaFile("file1", int64(len(content))), rng)
	if err != nil {
		t.Fatalf("OpenMedia() error: %v", err)
	}
	defer ms.Body.Close()

	if ms.StatusCode != http.StatusPartialContent {
		t.Fatalf("StatusCode = %d, want 206", ms.StatusCode)
	}
	got, _ := io.ReadAll(ms.Body)
	if string(got) != "56789" {
		t.Fatalf("body = %q, want 56789", got)
	}
	fd.mu.Lock()
	ranges := append([]string(nil), fd.rangeSeen...)
	fd.mu.Unlock()
	if len(ranges) != 1 || ranges[0] != "bytes=5-9" {
		t.Fatalf("upstream Range headers = %v, want [bytes=5-9]", ranges)
	}
}

func TestOpenMediaRangeNotSatisfiable(t *testing.T) {
	fd := newFakeDrive()
	fd.media["file1"] = []byte("short")

	c := newTestClient(t, fd, &fakeTokens{token: "tok"})
	// Ask for bytes far beyond the file.
	rng := &utils.ByteRange{Start: 100, End: 200, Length: 101}
	_, err := c.OpenMedia(context.Background(), mediaFile("file1", 1000), rng)
	if !errors.Is(err, ErrRangeNotSatisfiable) {
		t.Fatalf("OpenMedia() = %v, want ErrRangeNotSatisfiable", err)
	}
}

func TestOpenMediaMissingFile(t *testing.T) {
	fd := newFakeDrive()
	c := newTestClient(t, fd, &fakeTokens{token: "tok"})

	ms, err := c.OpenMedia(context.Background(), mediaFile("missing", 10), nil)
	if err == nil {
		ms.Body.Close()
		t.Fatal("expected an error")
	}
	apiErr, ok := AsAPIError(err)
	if !ok || !apiErr.IsNotFound() {
		t.Fatalf("error = %v, want a not-found APIError", err)
	}
}

func TestOpenMediaRefusesWorkspaceAndFolder(t *testing.T) {
	fd := newFakeDrive()
	c := newTestClient(t, fd, &fakeTokens{token: "tok"})

	doc := &File{ID: "doc1", Name: "Doc", MimeType: "application/vnd.google-apps-fake", CanDownload: true}
	doc.MimeType = "application/vnd.google-apps.document"
	if _, err := c.OpenMedia(context.Background(), doc, nil); !errors.Is(err, ErrWorkspaceFile) {
		t.Fatalf("workspace OpenMedia() = %v, want ErrWorkspaceFile", err)
	}

	folder := &File{ID: "f1", Name: "Folder", MimeType: "application/vnd.google-apps.folder", CanDownload: true}
	if _, err := c.OpenMedia(context.Background(), folder, nil); !errors.Is(err, ErrNotDownloadable) {
		t.Fatalf("folder OpenMedia() = %v, want ErrNotDownloadable", err)
	}

	if n := atomic.LoadInt32(&fd.requests); n != 0 {
		t.Fatalf("made %d upstream requests for undownloadable files, want 0", n)
	}
}

func TestClientStats(t *testing.T) {
	fd := newFakeDrive()
	fd.metadata[testID] = `{"id":"` + testID + `","name":"a.txt","mimeType":"text/plain","size":"1","capabilities":{"canDownload":true}}`
	c := newTestClient(t, fd, &fakeTokens{token: "tok"})

	if _, err := c.GetFile(context.Background(), testID); err != nil {
		t.Fatalf("GetFile() error: %v", err)
	}
	calls, refreshes := c.Stats()
	if calls != 1 || refreshes != 0 {
		t.Fatalf("Stats() = (%d, %d), want (1, 0)", calls, refreshes)
	}
}

func TestErrorMessagesNeverContainTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		// A hostile upstream echoes the Authorization header back.
		fmt.Fprintf(w, `{"error":{"code":401,"message":"bad token %s","errors":[{"reason":"authError"}]}}`, r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)

	c := New(Options{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: &fakeTokens{token: "ya29.SUPERSECRETTOKEN"}})
	_, err := c.GetFile(context.Background(), testID)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETTOKEN") {
		t.Fatalf("error message leaked the access token: %q", err.Error())
	}
}
