package utils

import (
	"strings"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"My Vacation Photo.jpg", "My Vacation Photo.jpg"},
		{"", DefaultFilename},
		{"   ", DefaultFilename},
		{"...", DefaultFilename},
		{"../etc/passwd", "passwd"},
		{`..\..\windows\system32\cmd.exe`, "cmd.exe"},
		{"dir/sub/file.txt", "file.txt"},
		{"quote\"name.txt", "quotename.txt"},
		{"single'quote.txt", "singlequote.txt"},
		{"back`tick.txt", "backtick.txt"},
		// A backslash is legal in a Drive name but is a path separator on
		// Windows, so the final component wins.
		{"back\\slash.txt", "slash.txt"},
		{"semi;colon.txt", "semi;colon.txt"},
		{"trailing dots...", "trailing dots"},
		{"  leading spaces.txt", "leading spaces.txt"},
		{"tab\tseparated.txt", "tab separated.txt"},
		{"null\x00byte.txt", "nullbyte.txt"},
		{"bell\x07.txt", "bell.txt"},
		{"newline\nname.txt", "newline name.txt"},
		{"carriage\rreturn.txt", "carriage return.txt"},
		{"CON", "_CON"},
		{"nul.txt", "_nul.txt"},
		{"COM1", "_COM1"},
		{"normal.txt", "normal.txt"},
		{"日本語のファイル.txt", "日本語のファイル.txt"},
		{"emoji 🎉 file.bin", "emoji 🎉 file.bin"},
		{"-leading-dash.txt", "leading-dash.txt"},
		{".hidden.txt", "hidden.txt"},
		{"name   with    many   spaces.txt", "name with many spaces.txt"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := SanitizeFilename(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got == "" {
				t.Fatal("SanitizeFilename returned empty string")
			}
			if strings.ContainsAny(got, "\r\n\x00") {
				t.Fatalf("SanitizeFilename(%q) = %q contains control characters", tc.in, got)
			}
		})
	}
}

func TestSanitizeFilenameTruncatesLongNames(t *testing.T) {
	long := strings.Repeat("a", 500) + ".pdf"
	got := SanitizeFilename(long)
	if n := len([]rune(got)); n > maxFilenameRunes {
		t.Fatalf("truncated name has %d runes, want <= %d", n, maxFilenameRunes)
	}
	if !strings.HasSuffix(got, ".pdf") {
		t.Fatalf("truncated name lost its extension: %q", got)
	}
}

func TestContentDispositionASCII(t *testing.T) {
	got := ContentDisposition("report.pdf")
	want := `attachment; filename="report.pdf"`
	if got != want {
		t.Fatalf("ContentDisposition() = %q, want %q", got, want)
	}
}

func TestContentDispositionUnicode(t *testing.T) {
	got := ContentDisposition("日本語.txt")
	if !strings.HasPrefix(got, "attachment; filename=\"") {
		t.Fatalf("missing ASCII fallback: %q", got)
	}
	if !strings.Contains(got, "filename*=UTF-8''") {
		t.Fatalf("missing RFC 5987 form: %q", got)
	}
	// The fallback must be pure ASCII.
	fallback := got[len(`attachment; filename="`):]
	fallback = fallback[:strings.IndexByte(fallback, '"')]
	for _, r := range fallback {
		if r > 0x7f {
			t.Fatalf("ASCII fallback contains non-ASCII rune %q: %q", r, fallback)
		}
	}
}

func TestContentDispositionNeverInjectsHeaders(t *testing.T) {
	// A malicious Drive name must not be able to add response headers.
	got := ContentDisposition("evil\r\nX-Injected: 0.0.0.0\r\n\r\nname.txt")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("Content-Disposition contains CR/LF: %q", got)
	}
	if !IsSafeHeaderValue(got) {
		t.Fatalf("Content-Disposition is not a safe header value: %q", got)
	}
}

func TestIsSafeHeaderValue(t *testing.T) {
	if !IsSafeHeaderValue("simple value") {
		t.Fatal("plain value reported unsafe")
	}
	if IsSafeHeaderValue("bad\r\nvalue") {
		t.Fatal("CRLF value reported safe")
	}
	if IsSafeHeaderValue("nul\x00value") {
		t.Fatal("NUL value reported safe")
	}
}
