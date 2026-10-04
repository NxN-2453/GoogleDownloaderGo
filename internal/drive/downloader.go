package drive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/utils"
)

// Errors returned by OpenMedia.
var (
	// ErrRangeNotSatisfiable indicates Drive rejected the relay's own range
	// request, which happens when the file changed size since the metadata
	// lookup. The caller should re-fetch metadata and retry.
	ErrRangeNotSatisfiable = errors.New("Google Drive rejected the byte range")
)

// MediaStream is an open, streaming view of a Drive file's bytes.
//
// The caller owns Body and must close it. The relay deliberately never buffers
// file content: Body is the upstream response body, and io.Copy moves it to
// the client.
type MediaStream struct {
	Body io.ReadCloser

	// StatusCode is 200 for a full response or 206 for a partial one.
	StatusCode int

	// ContentLength is the number of bytes in this response. It is -1 when
	// Drive does not report a length.
	ContentLength int64

	// ContentRange is the upstream Content-Range header, if any.
	ContentRange string

	// ContentType is the upstream Content-Type, if any. Google often reports
	// application/octet-stream regardless of the real type, so callers may
	// prefer the metadata MIME type.
	ContentType string

	// AcceptRanges mirrors the upstream Accept-Ranges header.
	AcceptRanges string

	// Range is the range that was requested, if any.
	Range *utils.ByteRange
}

// OpenMedia opens a media (alt=media) download for a file.
//
// When rng is non-nil the Range header is forwarded upstream and Google is
// expected to answer 206 Partial Content. This is what makes the relay's own
// range and resume support cheap: no local seeking, no re-downloading the
// prefix, no temporary files.
//
// The returned MediaStream must be closed by the caller. On any non-2xx
// response the body is closed and an *APIError (or a typed sentinel) is
// returned.
func (c *Client) OpenMedia(ctx context.Context, file *File, rng *utils.ByteRange) (*MediaStream, error) {
	if file == nil {
		return nil, errors.New("drive: nil file")
	}
	if err := CheckDownloadable(file); err != nil {
		return nil, err
	}

	r := request{
		op:     "files.get.media",
		method: http.MethodGet,
		rawURL: c.baseURL + "/files/" + file.ID,
		query: map[string][]string{
			"alt":               {"media"},
			"supportsAllDrives": {"true"},
		},
		// Any content type is acceptable: the relay passes the bytes through.
		accept:  "*/*",
		headers: map[string]string{},
		// A media request is not retried on 401 because the caller may have
		// already streamed bytes; the handler re-issues the whole request.
		noRetry: true,
	}
	if rng != nil {
		r.headers["Range"] = fmt.Sprintf("bytes=%d-%d", rng.Start, rng.End)
	}

	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		apiErr := c.decodeError("files.get.media", resp)
		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			return nil, fmt.Errorf("%w: %v", ErrRangeNotSatisfiable, apiErr)
		}
		return nil, apiErr
	}

	ms := &MediaStream{
		Body:          resp.Body,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentRange:  resp.Header.Get("Content-Range"),
		ContentType:   resp.Header.Get("Content-Type"),
		AcceptRanges:  resp.Header.Get("Accept-Ranges"),
		Range:         rng,
	}

	// Guard against a truncated stream: when Drive reports a length, a
	// mismatch with the requested range would silently corrupt a resumed
	// download, so surface it immediately rather than mid-transfer.
	if rng != nil && ms.ContentLength >= 0 && ms.ContentLength != rng.Length {
		if c.logger != nil {
			c.logger.Warn("drive returned an unexpected media length for the requested range",
				"file_id", file.ID,
				"requested", rng.Length,
				"reported", ms.ContentLength,
			)
		}
	}

	return ms, nil
}
