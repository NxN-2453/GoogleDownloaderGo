// Package utils contains the pure, dependency-free helpers shared by the rest
// of the relay: Drive URL parsing, filename sanitisation and HTTP range
// parsing. Everything here is deliberately side-effect free so it is trivial
// to unit test.
package utils

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Sentinel errors returned by ParseDriveInput. Handlers map these to HTTP
// status codes.
var (
	// ErrNotDriveURL is returned when the input looks like a URL but is not a
	// recognised Google Drive URL. This is the anti-proxy guard. It is an
	// error rather than a redirect to Google because a shorter path is a
	// smaller attack surface: the relay must never fetch a user supplied host.
	ErrNotDriveURL = errors.New("input is not a recognised Google Drive URL or file ID")

	// ErrFolderNotDownloadable is returned for Drive folder URLs.
	ErrFolderNotDownloadable = errors.New("Google Drive folders cannot be downloaded; supply a file ID")

	// ErrInvalidFileID is returned when an ID contains illegal characters or
	// has an implausible length.
	ErrInvalidFileID = errors.New("invalid Google Drive file ID")
)

// idCharsetRe matches the character set Google uses for Drive file IDs.
var idCharsetRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// allowedDriveHosts is the closed set of hosts the relay will parse an ID out
// of. Nothing else is ever contacted.
var allowedDriveHosts = map[string]bool{
	"drive.google.com":             true,
	"docs.google.com":              true,
	"drive.usercontent.google.com": true,
	"docs.googleusercontent.com":   true,
}

// docsPathKinds are the /docs.google.com/<kind>/d/<ID> path segments that map
// onto Drive files.
var docsPathKinds = map[string]bool{
	"document":     true,
	"spreadsheets": true,
	"presentation": true,
	"forms":        true,
	"drawings":     true,
	"file":         true,
}

// maxFileIDLength bounds the accepted ID length. Real Drive IDs are ~28-44
// characters; the ceiling is generous but finite so an attacker cannot push a
// megabyte of "ID" into a URL.
const maxFileIDLength = 128

// minFileIDLength rejects obviously fake IDs early. Short IDs do exist in
// tests and in some legacy items, so the floor stays low.
const minFileIDLength = 3

// ParseDriveInput accepts either a bare Google Drive file ID or one of the
// recognised Google Drive URL shapes and returns the file ID.
//
// Supported URL shapes:
//
//	https://drive.google.com/file/d/<ID>/view
//	https://drive.google.com/open?id=<ID>
//	https://drive.google.com/uc?id=<ID>&export=download
//	https://drive.google.com/thumbnail?id=<ID>
//	https://drive.google.com/drive/folders/<ID>        (rejected: folder)
//	https://drive.usercontent.google.com/download?id=<ID>
//	https://docs.google.com/document/d/<ID>/edit
//	https://docs.google.com/spreadsheets/d/<ID>/edit
//	https://docs.google.com/presentation/d/<ID>/edit
//	https://docs.google.com/forms/d/<ID>/edit
//	https://docs.google.com/drawings/d/<ID>/edit
//
// Any other URL - including any non-Google host - is rejected with
// ErrNotDriveURL so the relay can never be used as an open proxy.
func ParseDriveInput(raw string) (string, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return "", fmt.Errorf("%w: input is empty", ErrInvalidFileID)
	}
	if containsControlChars(input) {
		return "", fmt.Errorf("%w: input contains control characters", ErrInvalidFileID)
	}

	// Bare file ID: no scheme, no slash, no query.
	if !looksLikeURL(input) {
		if err := ValidateFileID(input); err != nil {
			return "", err
		}
		return input, nil
	}

	// From here on the input is a URL. It must parse, must be http/https, and
	// its host must be a Google Drive host.
	u, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("%w: malformed URL", ErrNotDriveURL)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%w: unsupported URL scheme %q (only https is accepted)", ErrNotDriveURL, u.Scheme)
	}
	// Embedded credentials (https://user:pass@drive.google.com/...) are not a
	// valid Drive URL shape and are a classic phishing/confusion trick.
	if u.User != nil {
		return "", fmt.Errorf("%w: URL must not contain embedded credentials", ErrNotDriveURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: URL has no host", ErrNotDriveURL)
	}
	if !allowedDriveHosts[host] {
		return "", fmt.Errorf("%w: host %q is not a Google Drive host", ErrNotDriveURL, host)
	}

	id, err := extractFromURL(u)
	if err != nil {
		return "", err
	}
	if err := ValidateFileID(id); err != nil {
		return "", err
	}
	return id, nil
}

// extractFromURL pulls the file ID out of a parsed, host-validated URL.
func extractFromURL(u *url.URL) (string, error) {
	path := strings.Trim(u.EscapedPath(), "/")
	segments := splitPath(path)

	// docs.google.com/<kind>/d/<ID>/...
	if host := strings.ToLower(u.Hostname()); host == "docs.google.com" || host == "docs.googleusercontent.com" {
		if len(segments) >= 3 && docsPathKinds[segments[0]] && segments[1] == "d" {
			return segments[2], nil
		}
		// Some docs URLs carry the ID in a query parameter instead.
		if id := firstQueryID(u); id != "" {
			return id, nil
		}
		return "", fmt.Errorf("%w: unrecognised Google Docs URL", ErrNotDriveURL)
	}

	// drive.google.com/file/d/<ID>/view
	if len(segments) >= 3 && segments[0] == "file" && segments[1] == "d" {
		return segments[2], nil
	}

	// drive.google.com/drive/folders/<ID>  (and /drive/u/0/folders/<ID>)
	for i, seg := range segments {
		if seg == "folders" && i+1 < len(segments) {
			// Report folders clearly instead of failing obscurely later.
			return "", ErrFolderNotDownloadable
		}
	}

	// Query-parameter forms: /open?id=, /uc?id=, /thumbnail?id=, /download?id=
	if id := firstQueryID(u); id != "" {
		return id, nil
	}

	return "", fmt.Errorf("%w: could not find a file ID in the URL", ErrNotDriveURL)
}

// firstQueryID returns the first recognised ID query parameter value.
func firstQueryID(u *url.URL) string {
	q := u.Query()
	for _, key := range []string{"id", "fileId", "file_id"} {
		if v := strings.TrimSpace(q.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

// ValidateFileID checks that an ID is plausible: bounded length, safe charset.
func ValidateFileID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: empty", ErrInvalidFileID)
	}
	if len(id) < minFileIDLength {
		return fmt.Errorf("%w: %q is too short", ErrInvalidFileID, truncateForError(id))
	}
	if len(id) > maxFileIDLength {
		return fmt.Errorf("%w: %d characters exceeds the %d character limit", ErrInvalidFileID, len(id), maxFileIDLength)
	}
	if !idCharsetRe.MatchString(id) {
		return fmt.Errorf("%w: %q contains characters outside [A-Za-z0-9_-]", ErrInvalidFileID, truncateForError(id))
	}
	return nil
}

// IsDriveURL reports whether raw parses as a supported Drive URL. Useful for
// tests and diagnostics.
func IsDriveURL(raw string) bool {
	_, err := ParseDriveInput(raw)
	return err == nil
}

// looksLikeURL reports whether the input should be treated as a URL rather
// than a bare file ID. Anything with a scheme separator, a slash, or a "?"
// counts as a URL attempt - including hostile ones - so that bad URLs are
// rejected explicitly instead of being mistaken for weird IDs.
func looksLikeURL(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	if strings.ContainsAny(s, "/?#") {
		return true
	}
	// "drive.google.com/..." without a scheme.
	lower := strings.ToLower(s)
	for _, h := range []string{"drive.google.com", "docs.google.com", "googleusercontent.com", "googleapis.com"} {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func truncateForError(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
