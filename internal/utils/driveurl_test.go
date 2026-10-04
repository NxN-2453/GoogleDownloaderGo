package utils

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDriveInputAccepts(t *testing.T) {
	const id = "1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW"

	tests := []struct {
		name  string
		input string
	}{
		{"bare id", id},
		{"bare id with surrounding spaces", "  " + id + "  "},
		{"file view url", "https://drive.google.com/file/d/" + id + "/view"},
		{"file view url with query", "https://drive.google.com/file/d/" + id + "/view?usp=sharing"},
		{"file preview", "https://drive.google.com/file/d/" + id + "/preview"},
		{"open id", "https://drive.google.com/open?id=" + id},
		{"uc export download", "https://drive.google.com/uc?id=" + id + "&export=download"},
		{"uc export with confirm token", "https://drive.google.com/uc?export=download&id=" + id + "&confirm=t"},
		{"thumbnail", "https://drive.google.com/thumbnail?id=" + id + "&sz=w1000"},
		{"usercontent download", "https://drive.usercontent.google.com/download?id=" + id + "&export=download"},
		{"docs document", "https://docs.google.com/document/d/" + id + "/edit"},
		{"docs spreadsheets", "https://docs.google.com/spreadsheets/d/" + id + "/edit#gid=0"},
		{"docs presentation", "https://docs.google.com/presentation/d/" + id + "/edit"},
		{"docs forms", "https://docs.google.com/forms/d/" + id + "/edit"},
		{"docs drawings", "https://docs.google.com/drawings/d/" + id + "/edit"},
		{"uppercase host", "https://DRIVE.GOOGLE.COM/file/d/" + id + "/view"},
		{"host with port", "https://drive.google.com:443/file/d/" + id + "/view"},
		{"id with underscore and dash", "abc_123-XYZ"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDriveInput(tc.input)
			if err != nil {
				t.Fatalf("ParseDriveInput(%q) error: %v", tc.input, err)
			}
			if got != id && tc.name != "id with underscore and dash" {
				t.Fatalf("ParseDriveInput(%q) = %q, want %q", tc.input, got, id)
			}
		})
	}
}

func TestParseDriveInputRejects(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"empty", "", ErrInvalidFileID},
		{"whitespace", "   ", ErrInvalidFileID},
		{"too short", "ab", ErrInvalidFileID},
		{"illegal characters", "abc$def", ErrInvalidFileID},
		{"path traversal attempt", "../../etc/passwd", ErrNotDriveURL},
		{"absolute path", "/etc/passwd", ErrNotDriveURL},

		// SSRF / open-proxy guard: none of these may be fetched.
		{"arbitrary http url", "http://example.com/file.zip", ErrNotDriveURL},
		{"arbitrary https url", "https://example.com/file.zip", ErrNotDriveURL},
		{"https scheme on drive host is required", "http://drive.google.com/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"file scheme", "file:///etc/passwd", ErrNotDriveURL},
		{"ftp scheme", "ftp://drive.google.com/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"lookalike host", "https://drive.google.com.evil.tld/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"prefix lookalike host", "https://notdrive.google.com/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"subdomain of drive", "https://evil.drive.google.com/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"metadata service", "https://169.254.169.254/latest/meta-data/", ErrNotDriveURL},
		{"localhost", "https://localhost:8080/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"internal hostname", "https://internal.corp/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"credentials in url", "https://user:pass@drive.google.com/file/d/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW/view", ErrNotDriveURL},
		{"googleapis direct", "https://www.googleapis.com/drive/v3/files/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW", ErrNotDriveURL},

		{"folder url", "https://drive.google.com/drive/folders/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW", ErrFolderNotDownloadable},
		{"folder url with user index", "https://drive.google.com/drive/u/0/folders/1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW", ErrFolderNotDownloadable},

		{"drive root", "https://drive.google.com", ErrNotDriveURL},
		{"no id in url", "https://drive.google.com/drive/my-drive", ErrNotDriveURL},
		{"docs url without id", "https://docs.google.com/document/u/0/", ErrNotDriveURL},
		{"id too long", "https://drive.google.com/file/d/" + strings.Repeat("a", 200) + "/view", ErrInvalidFileID},
		{"control characters", "abc\x00def", ErrInvalidFileID},
		{"newline injection", "1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW\r\nX-Evil: 1", ErrInvalidFileID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDriveInput(tc.input)
			if err == nil {
				t.Fatalf("ParseDriveInput(%q) = %q, want error %v", tc.input, got, tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseDriveInput(%q) error = %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateFileID(t *testing.T) {
	if err := ValidateFileID("1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvW"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	if err := ValidateFileID(strings.Repeat("a", 129)); err == nil {
		t.Fatal("over-long id accepted")
	}
	if err := ValidateFileID("has space"); err == nil {
		t.Fatal("id with space accepted")
	}
	if err := ValidateFileID("semi;colon"); err == nil {
		t.Fatal("id with semicolon accepted")
	}
}

func TestIsDriveURL(t *testing.T) {
	if !IsDriveURL("https://drive.google.com/file/d/abc123/view") {
		t.Fatal("expected true for a Drive URL")
	}
	if IsDriveURL("https://example.com/file.zip") {
		t.Fatal("expected false for a non-Drive URL")
	}
}
