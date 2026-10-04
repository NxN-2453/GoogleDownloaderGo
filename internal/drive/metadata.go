package drive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/NxN-2453/GoogleDownloaderGo/internal/utils"
)

// Errors specific to metadata lookup.
var (
	// ErrWorkspaceFile indicates a Google Docs/Sheets/Slides file, which has no
	// binary content to stream.
	ErrWorkspaceFile = errors.New("Google Workspace files cannot be streamed directly")

	// ErrNotDownloadable indicates Drive refused a direct download.
	ErrNotDownloadable = errors.New("this file cannot be downloaded")

	// ErrShortcutLoop indicates a shortcut chain that never terminates.
	ErrShortcutLoop = errors.New("shortcut chain is too deep or circular")
)

// metadataFields is the field mask requested from Drive. Keeping it explicit
// avoids the large default payload and documents exactly what the relay uses.
const metadataFields = "id,name,mimeType,size,md5Checksum,modifiedTime,createdTime," +
	"trashed,explicitlyTrashed,driveId,webViewLink,webContentLink," +
	"capabilities(canDownload),shortcutDetails(targetId,targetMimeType),owners(displayName,emailAddress)"

// File is the relay's view of a Google Drive file.
type File struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MimeType     string `json:"mime_type"`
	Size         int64  `json:"size"`
	SizeKnown    bool   `json:"size_known"`
	MD5Checksum  string `json:"md5_checksum,omitempty"`
	ModifiedTime string `json:"modified_time,omitempty"`
	CreatedTime  string `json:"created_time,omitempty"`
	DriveID      string `json:"drive_id,omitempty"`
	WebViewLink  string `json:"web_view_link,omitempty"`
	Owner        string `json:"owner,omitempty"`

	// Trashed files are still returned by files.get; the relay refuses them.
	Trashed bool `json:"trashed"`

	// CanDownload reflects Drive's capabilities.canDownload flag.
	CanDownload bool `json:"can_download"`

	// IsGoogleWorkspace marks Docs/Sheets/Slides/Forms/Drawings and folders.
	IsGoogleWorkspace bool `json:"is_google_workspace"`
	// IsFolder marks Drive folders.
	IsFolder bool `json:"is_folder"`
	// IsShortcut marks shortcut entries (resolved transparently on lookup).
	IsShortcut bool `json:"is_shortcut"`

	// ExportSuggestion, when non-empty, describes how to obtain a downloadable
	// rendition of a Workspace file.
	ExportSuggestion *ExportSuggestion `json:"export_suggestion,omitempty"`

	// Raw is the decoded Drive resource, useful for diagnostics.
	Raw map[string]any `json:"-"`
}

// ExportSuggestion tells the operator which export would produce a
// downloadable file for a Google Workspace document.
type ExportSuggestion struct {
	MimeType  string `json:"mime_type"`
	Extension string `json:"extension"`
}

// workspaceExports maps Docs editor MIME types to a sensible export target.
var workspaceExports = map[string]ExportSuggestion{
	"application/vnd.google-apps.document":     {MimeType: "application/pdf", Extension: ".pdf"},
	"application/vnd.google-apps.spreadsheet":  {MimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Extension: ".xlsx"},
	"application/vnd.google-apps.presentation": {MimeType: "application/vnd.openxmlformats-officedocument.presentationml.presentation", Extension: ".pptx"},
	"application/vnd.google-apps.drawing":      {MimeType: "image/png", Extension: ".png"},
	"application/vnd.google-apps.script":       {MimeType: "application/vnd.google-apps.script+json", Extension: ".json"},
}

// IsGoogleWorkspaceMime reports whether a MIME type is a Docs editor type
// (which has no directly downloadable byte stream).
func IsGoogleWorkspaceMime(mime string) bool {
	if !strings.HasPrefix(mime, "application/vnd.google-apps.") {
		return false
	}
	// Folders and shortcuts are Google-owned types but are handled separately.
	switch mime {
	case "application/vnd.google-apps.folder", "application/vnd.google-apps.shortcut":
		return false
	}
	return true
}

// IsFolderMime reports whether a MIME type is a Drive folder.
func IsFolderMime(mime string) bool { return mime == "application/vnd.google-apps.folder" }

// IsShortcutMime reports whether a MIME type is a Drive shortcut.
func IsShortcutMime(mime string) bool { return mime == "application/vnd.google-apps.shortcut" }

// fileResource mirrors the Drive files.get JSON payload.
type fileResource struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MimeType     string `json:"mimeType"`
	Size         string `json:"size"`
	MD5Checksum  string `json:"md5Checksum"`
	ModifiedTime string `json:"modifiedTime"`
	CreatedTime  string `json:"createdTime"`
	DriveID      string `json:"driveId"`
	WebViewLink  string `json:"webViewLink"`
	Trashed      bool   `json:"trashed"`
	Capabilities *struct {
		CanDownload bool `json:"canDownload"`
	} `json:"capabilities"`
	ShortcutDetails *struct {
		TargetID       string `json:"targetId"`
		TargetMimeType string `json:"targetMimeType"`
	} `json:"shortcutDetails"`
	Owners []struct {
		DisplayName  string `json:"displayName"`
		EmailAddress string `json:"emailAddress"`
	} `json:"owners"`
}

// maxShortcutHops bounds shortcut resolution so a malicious or broken chain
// cannot loop forever.
const maxShortcutHops = 5

// GetFile fetches metadata for a file ID.
//
// Shortcuts are resolved transparently: the returned File describes the
// shortcut's target, with the original ID preserved in Raw["shortcut_id"].
// Shared-drive items are supported (supportsAllDrives=true).
func (c *Client) GetFile(ctx context.Context, id string) (*File, error) {
	if err := utils.ValidateFileID(id); err != nil {
		return nil, err
	}

	current := id
	for hop := 0; hop <= maxShortcutHops; hop++ {
		res, err := c.getFileOnce(ctx, current)
		if err != nil {
			return nil, err
		}

		if res.ShortcutDetails != nil && res.ShortcutDetails.TargetID != "" {
			if hop == maxShortcutHops {
				return nil, ErrShortcutLoop
			}
			current = res.ShortcutDetails.TargetID
			if err := utils.ValidateFileID(current); err != nil {
				return nil, fmt.Errorf("%w: shortcut target is not a valid file ID", ErrShortcutLoop)
			}
			continue
		}

		return c.toFile(res, id), nil
	}
	return nil, ErrShortcutLoop
}

// getFileOnce performs a single files.get call.
func (c *Client) getFileOnce(ctx context.Context, id string) (*fileResource, error) {
	r := request{
		op:     "files.get",
		method: http.MethodGet,
		rawURL: c.baseURL + "/files/" + id,
		query: map[string][]string{
			"fields":            {metadataFields},
			"supportsAllDrives": {"true"},
		},
		accept: "application/json",
	}

	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	defer drain(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, c.decodeError("files.get", resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("drive files.get: reading metadata: %w", err)
	}

	var res fileResource
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("drive files.get: decoding metadata: %w", err)
	}
	if res.ID == "" {
		res.ID = id
	}
	return &res, nil
}

// toFile converts a Drive resource into the relay's File view.
func (c *Client) toFile(res *fileResource, requestedID string) *File {
	f := &File{
		ID:           res.ID,
		Name:         res.Name,
		MimeType:     res.MimeType,
		MD5Checksum:  res.MD5Checksum,
		ModifiedTime: res.ModifiedTime,
		CreatedTime:  res.CreatedTime,
		DriveID:      res.DriveID,
		WebViewLink:  res.WebViewLink,
		Trashed:      res.Trashed,
	}

	// capabilities.canDownload is authoritative when present; older API
	// responses omit it, in which case we assume a download is worth trying.
	f.CanDownload = true
	if res.Capabilities != nil {
		f.CanDownload = res.Capabilities.CanDownload
	}
	if len(res.Owners) > 0 {
		f.Owner = res.Owners[0].EmailAddress
		if f.Owner == "" {
			f.Owner = res.Owners[0].DisplayName
		}
	}

	if res.Size != "" {
		if n, err := strconv.ParseInt(res.Size, 10, 64); err == nil && n >= 0 {
			f.Size = n
			f.SizeKnown = true
		}
	}
	// Workspace documents report no size (or "0"); the real size is only known
	// after an export, so leave SizeKnown false for them.
	if IsGoogleWorkspaceMime(f.MimeType) && f.Size == 0 {
		f.SizeKnown = false
	}

	f.IsFolder = IsFolderMime(f.MimeType)
	f.IsGoogleWorkspace = IsGoogleWorkspaceMime(f.MimeType)
	f.IsShortcut = IsShortcutMime(f.MimeType)

	if sug, ok := workspaceExports[f.MimeType]; ok {
		s := sug
		f.ExportSuggestion = &s
	}

	raw := map[string]any{
		"id":             f.ID,
		"name":           f.Name,
		"mimeType":       f.MimeType,
		"driveId":        f.DriveID,
		"trashed":        f.Trashed,
		"modifiedTime":   f.ModifiedTime,
		"canDownload":    f.CanDownload,
		"requestedId":    requestedID,
		"isWorkspaceDoc": f.IsGoogleWorkspace,
	}
	if requestedID != f.ID {
		raw["shortcut_id"] = requestedID
	}
	f.Raw = raw

	return f
}

// CheckDownloadable reports why a file cannot be streamed, or nil when it can.
//
// The relay prefers an explicit, actionable error over letting Drive return an
// opaque 403 mid-transfer, and it never buffers a Workspace export.
func CheckDownloadable(f *File) error {
	if f == nil {
		return errors.New("drive: no file metadata")
	}

	// The MIME type is treated as authoritative rather than trusting the
	// derived booleans, so the check stays correct even for a File that was
	// constructed by hand (for example in a handler or a test).
	isFolder := f.IsFolder || IsFolderMime(f.MimeType)
	isWorkspace := f.IsGoogleWorkspace || IsGoogleWorkspaceMime(f.MimeType)

	switch {
	case isFolder:
		return fmt.Errorf("%w: %q is a folder, not a file", ErrNotDownloadable, f.Name)
	case isWorkspace:
		sug := f.ExportSuggestion
		if sug == nil {
			if found, ok := workspaceExports[f.MimeType]; ok {
				sug = &found
			}
		}
		if sug != nil {
			return fmt.Errorf("%w: %q is a Google Workspace document (%s); export it as %s (%s) instead",
				ErrWorkspaceFile, f.Name, f.MimeType, sug.MimeType, sug.Extension)
		}
		return fmt.Errorf("%w: %q is a Google Workspace document (%s)", ErrWorkspaceFile, f.Name, f.MimeType)
	case f.Trashed:
		return fmt.Errorf("%w: %q is in the trash", ErrNotDownloadable, f.Name)
	case !f.CanDownload:
		return fmt.Errorf("%w: Google Drive reports that the configured account cannot download %q", ErrNotDownloadable, f.Name)
	}
	return nil
}
