package config

import (
	"encoding/json"
	"log/slog"
)

// redacted is the placeholder used everywhere a secret value would otherwise
// be printed.
const redacted = "[REDACTED]"

// Secret wraps a sensitive string (OAuth token, client secret, API key) so it
// cannot leak by accident.
//
// A Secret implements fmt.Stringer, fmt.GoStringer, slog.LogValuer and
// json.Marshaler, all of which render the redaction placeholder. The only way
// to obtain the real value is an explicit call to Reveal, which makes every
// potential leak site greppable.
type Secret string

// String implements fmt.Stringer.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return redacted
}

// GoString implements fmt.GoStringer, used by the %#v verb.
func (s Secret) GoString() string { return s.String() }

// LogValue implements slog.LogValuer so structured logs redact by default.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// MarshalJSON implements json.Marshaler. Tokens can never be serialised into
// an API response.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Reveal returns the underlying secret. Use it only at the point where the
// value is handed to Google, never for logging or responses.
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is unset.
func (s Secret) IsZero() bool { return len(s) == 0 }

// Set assigns the secret value.
func (s *Secret) Set(v string) { *s = Secret(v) }
