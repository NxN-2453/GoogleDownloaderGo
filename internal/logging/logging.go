// Package logging builds the relay's structured logger and provides helpers
// that make it hard to leak credentials into logs.
package logging

import (
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// sensitiveKeys are attribute names that must never be rendered verbatim.
var sensitiveKeys = map[string]bool{
	"access_token":        true,
	"refresh_token":       true,
	"client_secret":       true,
	"api_key":             true,
	"apikey":              true,
	"authorization":       true,
	"token":               true,
	"secret":              true,
	"key":                 true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"id_token":            true,
	"resource_key":        true,
	"resourcekey":         true,
	"session":             true,
	"password":            true,
	"key_query_parameter": true,
}

// sensitiveQueryParams are query parameters scrubbed from any URL that is
// logged, such as /download?id=...&key=...
var sensitiveQueryParams = []string{"key", "api_key", "apikey", "access_token", "token", "resourcekey"}

var (
	bearerRe = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-~+/=]+`)
	ya29Re   = regexp.MustCompile(`\bya29\.[A-Za-z0-9._\-]+`)
	// Google OAuth client secrets look like GOCSPX-xxxxxxxxxxxxxxxxxxxx.
	gocspxRe = regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9._\-]+`)
	// Long opaque tokens (JWT-ish or refresh-token-ish).
	longTokRe = regexp.MustCompile(`\b1//[A-Za-z0-9._\-]{10,}`)
)

// ParseLevel converts a level name to an slog.Level, defaulting to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New creates the application logger. format is "text" or "json".
func New(w io.Writer, level slog.Level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactAttr,
	}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

// redactAttr blanks out values of attributes whose key looks sensitive, and
// scrubs token-shaped substrings from every string value. This is defence in
// depth: the code should never log a token in the first place.
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, "[REDACTED]")
	}
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, Scrub(a.Value.String()))
	case slog.KindGroup:
		return a
	default:
		return a
	}
}

// Scrub removes credentials from an arbitrary string. Use it on error
// messages and URLs that originate outside the relay.
func Scrub(s string) string {
	if s == "" {
		return s
	}
	s = bearerRe.ReplaceAllString(s, "Bearer [REDACTED]")
	s = ya29Re.ReplaceAllString(s, "[REDACTED]")
	s = gocspxRe.ReplaceAllString(s, "[REDACTED]")
	s = longTokRe.ReplaceAllString(s, "[REDACTED]")
	s = scrubQuery(s)
	return s
}

// scrubQuery rewrites the values of credential-bearing query parameters.
func scrubQuery(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	lower := strings.ToLower(s)
	changed := false
	for _, p := range sensitiveQueryParams {
		needle := p + "="
		idx := 0
		for {
			i := strings.Index(lower[idx:], needle)
			if i < 0 {
				break
			}
			start := idx + i + len(needle)
			end := start
			for end < len(s) && !strings.ContainsRune("&#\"' \t", rune(s[end])) {
				end++
			}
			if end > start {
				s = s[:start] + "[REDACTED]" + s[end:]
				lower = strings.ToLower(s)
				changed = true
			}
			idx = start + len("[REDACTED]")
			if idx >= len(s) {
				break
			}
		}
	}
	if !changed {
		return s
	}
	return s
}
