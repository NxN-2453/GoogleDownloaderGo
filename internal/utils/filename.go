package utils

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultFilename is used when a Drive name sanitises down to nothing.
const DefaultFilename = "download.bin"

// maxFilenameRunes bounds the filename stored in the Content-Disposition
// header. Long names waste header space and some clients truncate anyway.
const maxFilenameRunes = 180

// SanitizeFilename makes a Drive file name safe to place in a response header
// and on disk.
//
// It removes path traversal, control characters, quotes and newlines (the
// classic header-injection vector), collapses whitespace, trims leading dots
// and hyphens (hidden files / option-looking names), and bounds the length.
// The result is never empty: it falls back to DefaultFilename.
func SanitizeFilename(name string) string {
	if name == "" {
		return DefaultFilename
	}

	// Drop path components. Google Drive file names cannot contain '/', but a
	// backslash is legal in a Drive name and IS a path separator on Windows.
	// Stripping to the final component is the conservative choice: it protects
	// Windows clients from a name like `..\..\cmd.exe` at the cost of mangling
	// an unusual name that legitimately contains a backslash.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}

	var b strings.Builder
	b.Grow(len(name))
	lastSpace := false
	writeSpace := func() {
		if lastSpace || b.Len() == 0 {
			return
		}
		lastSpace = true
		b.WriteRune(' ')
	}

	for _, r := range name {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || unicode.IsSpace(r):
			// Newlines are the header-injection vector; collapse all
			// whitespace to a single space.
			writeSpace()
		case unicode.IsControl(r):
			continue
		case r == '"' || r == '\'' || r == '`':
			// Quotes would break out of the quoted-string form.
			continue
		default:
			lastSpace = false
			b.WriteRune(r)
		}
	}

	out := strings.TrimSpace(b.String())
	out = strings.TrimLeft(out, ".-")
	out = strings.TrimRight(out, ". ")

	// Windows reserved device names would be unusable when saved locally.
	if isWindowsReserved(out) {
		out = "_" + out
	}

	out = truncateRunes(out, maxFilenameRunes)
	if out == "" {
		return DefaultFilename
	}
	return out
}

// isWindowsReserved reports whether the name is a reserved DOS device name.
func isWindowsReserved(name string) bool {
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	}
	return false
}

// truncateRunes cuts s to at most max runes, keeping a short file extension
// intact so truncated names still describe their content.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}

	ext := ""
	if dot := strings.LastIndexByte(s, '.'); dot > 0 && len(s)-dot <= 12 {
		// Only treat it as an extension if it is short and contains no space.
		if strings.Count(s[dot+1:], " ") == 0 {
			ext = s[dot:]
		}
	}

	budget := max - utf8.RuneCountInString(ext)
	if budget < 1 {
		budget = max
		ext = ""
	}
	return string([]rune(s)[:budget]) + ext
}

// IsSafeHeaderValue reports whether s can be placed in an HTTP header value
// without risking response splitting.
func IsSafeHeaderValue(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ContentDisposition builds an RFC 6266 / RFC 5987 Content-Disposition value
// for an attachment download.
//
// It emits an ASCII fallback in `filename=` and the full UTF-8 name in
// `filename*=UTF-8”...` so non-ASCII Drive names survive on every client
// while staying header-injection safe.
func ContentDisposition(name string) string {
	safe := SanitizeFilename(name)
	ascii := toASCII(safe)
	if ascii == "" {
		ascii = DefaultFilename
	}
	encoded := rfc5987Encode(safe)

	var b strings.Builder
	b.WriteString("attachment; filename=\"")
	b.WriteString(ascii)
	b.WriteString("\"")
	if encoded != ascii {
		b.WriteString("; filename*=UTF-8''")
		b.WriteString(encoded)
	}
	return b.String()
}

// toASCII replaces non-ASCII runes with '_' for the legacy filename= field.
func toASCII(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80 && r >= 0x20 && r != '"' && r != '\\':
			b.WriteRune(r)
		case r == '"' || r == '\\':
			b.WriteByte('_')
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// rfc5987Encode percent-encodes a filename for the filename* parameter.
func rfc5987Encode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAttrChar(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper(c >> 4))
		b.WriteByte(hexUpper(c & 0x0f))
	}
	return b.String()
}

func isAttrChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case strings.IndexByte("!#$&+-.^_`|~", c) >= 0:
		return true
	default:
		return false
	}
}

func hexUpper(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}
