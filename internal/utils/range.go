package utils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Range parsing errors. Handlers map ErrNoOverlap to 416 and the rest to 400.
var (
	ErrNoRangeHeader    = errors.New("no Range header")
	ErrInvalidRange     = errors.New("invalid Range header")
	ErrNoOverlap        = errors.New("requested range not satisfiable")
	ErrMultipleRanges   = errors.New("multiple ranges are not supported")
	ErrUnknownRangeUnit = errors.New("unsupported range unit")
)

// ByteRange is a fully resolved, inclusive byte range. Offset and Length are
// always concrete: open-ended requests are resolved against the file size.
type ByteRange struct {
	Start  int64 // inclusive
	End    int64 // inclusive
	Length int64 // End - Start + 1
}

// ContentRange renders the Content-Range header value for a response.
func (r ByteRange) ContentRange(size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.Start, r.End, size)
}

// ParseRange parses an HTTP Range header against a known file size.
//
// Supported forms (RFC 9110 section 14.1.2):
//
//	bytes=0-          the whole file
//	bytes=100-        from 100 to the end
//	bytes=100-500     an explicit window
//	bytes=-500        the final 500 bytes
//
// Only a single range is supported. A multi-range request is rejected with
// ErrMultipleRanges rather than silently truncated, because a
// multipart/byteranges response would defeat streaming and resumability for
// the large files this relay targets.
//
// A syntactically valid but unsatisfiable range (for example bytes=999- on a
// 100 byte file) returns ErrNoOverlap so the caller can emit 416 with a
// Content-Range of "bytes */<size>".
func ParseRange(header string, size int64) (ByteRange, error) {
	h := strings.TrimSpace(header)
	if h == "" {
		return ByteRange{}, ErrNoRangeHeader
	}

	unit, spec, ok := strings.Cut(h, "=")
	if !ok {
		return ByteRange{}, fmt.Errorf("%w: missing '='", ErrInvalidRange)
	}
	if !strings.EqualFold(strings.TrimSpace(unit), "bytes") {
		return ByteRange{}, fmt.Errorf("%w: %q", ErrUnknownRangeUnit, strings.TrimSpace(unit))
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ByteRange{}, fmt.Errorf("%w: empty range set", ErrInvalidRange)
	}
	if strings.Contains(spec, ",") {
		return ByteRange{}, ErrMultipleRanges
	}

	startStr, endStr, ok := strings.Cut(spec, "-")
	if !ok {
		return ByteRange{}, fmt.Errorf("%w: missing '-'", ErrInvalidRange)
	}
	startStr = strings.TrimSpace(startStr)
	endStr = strings.TrimSpace(endStr)

	if size < 0 {
		return ByteRange{}, fmt.Errorf("%w: negative file size", ErrInvalidRange)
	}

	switch {
	case startStr == "" && endStr == "":
		return ByteRange{}, fmt.Errorf("%w: empty range", ErrInvalidRange)

	case startStr == "":
		// Suffix range: the final N bytes.
		n, err := parseNonNegativeInt(endStr)
		if err != nil {
			return ByteRange{}, fmt.Errorf("%w: %v", ErrInvalidRange, err)
		}
		if n == 0 {
			// "bytes=-0" is unsatisfiable by definition.
			return ByteRange{}, ErrNoOverlap
		}
		if size == 0 {
			return ByteRange{}, ErrNoOverlap
		}
		if n > size {
			n = size
		}
		return ByteRange{Start: size - n, End: size - 1, Length: n}, nil

	case endStr == "":
		// Open ended: from start to the end of the file.
		start, err := parseNonNegativeInt(startStr)
		if err != nil {
			return ByteRange{}, fmt.Errorf("%w: %v", ErrInvalidRange, err)
		}
		if start >= size {
			return ByteRange{}, ErrNoOverlap
		}
		return ByteRange{Start: start, End: size - 1, Length: size - start}, nil

	default:
		start, err := parseNonNegativeInt(startStr)
		if err != nil {
			return ByteRange{}, fmt.Errorf("%w: %v", ErrInvalidRange, err)
		}
		end, err := parseNonNegativeInt(endStr)
		if err != nil {
			return ByteRange{}, fmt.Errorf("%w: %v", ErrInvalidRange, err)
		}
		if start > end {
			return ByteRange{}, fmt.Errorf("%w: start %d is after end %d", ErrInvalidRange, start, end)
		}
		if start >= size {
			return ByteRange{}, ErrNoOverlap
		}
		if end >= size {
			// Clamp to the end of the file, as RFC 9110 requires.
			end = size - 1
		}
		return ByteRange{Start: start, End: end, Length: end - start + 1}, nil
	}
}

// parseNonNegativeInt parses a decimal byte offset, rejecting signs,
// whitespace and values that overflow int64.
func parseNonNegativeInt(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty number")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid number %q", s)
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("number out of range %q", s)
	}
	return n, nil
}
