package utils

import (
	"errors"
	"testing"
)

func TestParseRange(t *testing.T) {
	const size = 1000

	tests := []struct {
		name    string
		header  string
		want    ByteRange
		wantErr error
	}{
		{name: "empty header", header: "", wantErr: ErrNoRangeHeader},
		{name: "whitespace only", header: "   ", wantErr: ErrNoRangeHeader},

		{name: "full range", header: "bytes=0-", want: ByteRange{0, 999, 1000}},
		{name: "open ended", header: "bytes=100-", want: ByteRange{100, 999, 900}},
		{name: "closed window", header: "bytes=100-500", want: ByteRange{100, 500, 401}},
		{name: "single byte", header: "bytes=0-0", want: ByteRange{0, 0, 1}},
		{name: "last byte", header: "bytes=999-999", want: ByteRange{999, 999, 1}},
		{name: "suffix range", header: "bytes=-500", want: ByteRange{500, 999, 500}},
		{name: "suffix larger than file", header: "bytes=-5000", want: ByteRange{0, 999, 1000}},
		{name: "end clamped to size", header: "bytes=900-99999", want: ByteRange{900, 999, 100}},
		{name: "uppercase unit", header: "BYTES=0-99", want: ByteRange{0, 99, 100}},
		{name: "surrounding whitespace", header: "  bytes=0-99  ", want: ByteRange{0, 99, 100}},
		{name: "whitespace around numbers", header: "bytes= 0 - 99 ", want: ByteRange{0, 99, 100}},

		{name: "missing equals", header: "bytes0-99", wantErr: ErrInvalidRange},
		{name: "empty set", header: "bytes=", wantErr: ErrInvalidRange},
		{name: "empty range", header: "bytes=-", wantErr: ErrInvalidRange},
		{name: "start after end", header: "bytes=500-100", wantErr: ErrInvalidRange},
		{name: "negative start", header: "bytes=-1-100", wantErr: ErrInvalidRange},
		{name: "non numeric", header: "bytes=abc-100", wantErr: ErrInvalidRange},
		{name: "non numeric end", header: "bytes=0-abc", wantErr: ErrInvalidRange},
		{name: "float", header: "bytes=0.5-100", wantErr: ErrInvalidRange},
		{name: "overflow", header: "bytes=99999999999999999999999-", wantErr: ErrInvalidRange},
		{name: "unknown unit", header: "items=0-10", wantErr: ErrUnknownRangeUnit},
		{name: "multiple ranges", header: "bytes=0-10,20-30", wantErr: ErrMultipleRanges},

		{name: "start beyond file", header: "bytes=1000-", wantErr: ErrNoOverlap},
		{name: "start beyond file closed", header: "bytes=2000-3000", wantErr: ErrNoOverlap},
		{name: "zero length suffix", header: "bytes=-0", wantErr: ErrNoOverlap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRange(tc.header, size)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseRange(%q) error = %v, want %v", tc.header, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRange(%q) unexpected error: %v", tc.header, err)
			}
			if got != tc.want {
				t.Fatalf("ParseRange(%q) = %+v, want %+v", tc.header, got, tc.want)
			}
			if got.Length != got.End-got.Start+1 {
				t.Fatalf("ParseRange(%q) inconsistent length: %+v", tc.header, got)
			}
		})
	}
}

func TestParseRangeZeroSizeFile(t *testing.T) {
	if _, err := ParseRange("bytes=0-", 0); !errors.Is(err, ErrNoOverlap) {
		t.Fatalf("empty file: error = %v, want ErrNoOverlap", err)
	}
	if _, err := ParseRange("bytes=-10", 0); !errors.Is(err, ErrNoOverlap) {
		t.Fatalf("empty file suffix: error = %v, want ErrNoOverlap", err)
	}
}

func TestByteRangeContentRange(t *testing.T) {
	r := ByteRange{Start: 100, End: 499, Length: 400}
	if got, want := r.ContentRange(1000), "bytes 100-499/1000"; got != want {
		t.Fatalf("ContentRange() = %q, want %q", got, want)
	}
}
