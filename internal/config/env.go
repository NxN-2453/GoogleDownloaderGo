package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultEnvFile is loaded automatically when present.
const DefaultEnvFile = ".env"

// EnvFileEnv is the variable that overrides the .env path. It is also read
// from a literal ".env" line, so an env file may point at another env file.
const EnvFileVar = "RELAY_ENV_FILE"

// LoadEnvFile reads a dotenv-style file into the process environment.
//
// Rules:
//   - Values already present in the real environment are never overwritten, so
//     `GOOGLE_ACCESS_TOKEN=... ./relay` beats the file.
//   - A missing file is not an error; it returns (false, nil).
//   - `export KEY=value` is accepted.
//   - Blank lines and lines starting with '#' are ignored.
//   - Values may be wrapped in matching single or double quotes. Double-quoted
//     values support \n, \t, \r and \\ escapes; single-quoted values are
//     literal.
//   - Surrounding whitespace around the key is trimmed and whitespace before a
//     comment introduced by " #" is trimmed.
//
// It returns true when a file was actually read.
func LoadEnvFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open env file %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow long lines (a PEM blob in an env file is unusual but legal).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		key, val, ok, err := parseEnvLine(sc.Text())
		if err != nil {
			return false, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if !ok {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			// Real environment wins.
			continue
		}
		if err := os.Setenv(key, val); err != nil {
			return false, fmt.Errorf("set %s: %w", key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("read env file %s: %w", path, err)
	}
	return true, nil
}

// parseEnvLine parses a single dotenv line. ok is false for blank lines and
// comments.
func parseEnvLine(raw string) (key, value string, ok bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	line = strings.TrimPrefix(line, "export ")
	line = strings.TrimSpace(line)

	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false, fmt.Errorf("malformed line (expected KEY=value)")
	}
	key = strings.TrimSpace(line[:eq])
	if !validEnvKey(key) {
		return "", "", false, fmt.Errorf("invalid variable name %q", key)
	}
	value = strings.TrimSpace(line[eq+1:])

	switch {
	case strings.HasPrefix(value, `"`):
		// Double quoted: unescape, must be terminated.
		end := strings.LastIndexByte(value, '"')
		if end == 0 {
			return "", "", false, fmt.Errorf("unterminated double quote for %s", key)
		}
		value = unescapeDoubleQuoted(value[1:end])
	case strings.HasPrefix(value, `'`):
		end := strings.LastIndexByte(value, '\'')
		if end == 0 {
			return "", "", false, fmt.Errorf("unterminated single quote for %s", key)
		}
		value = value[1:end]
	default:
		// Strip a trailing comment introduced by " #".
		if i := strings.Index(value, " #"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		if i := strings.Index(value, "\t#"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
	}
	return key, value, true, nil
}

func unescapeDoubleQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// AutoLoadEnvFile loads the env file, honouring RELAY_ENV_FILE, then
// <exe dir>/.env, then ./.env. It returns the path that was loaded, if any.
func AutoLoadEnvFile() (string, error) {
	if p := strings.TrimSpace(os.Getenv(EnvFileVar)); p != "" {
		ok, err := LoadEnvFile(p)
		if err != nil {
			return "", err
		}
		if ok {
			return p, nil
		}
		// An explicitly requested file that does not exist is an error: the
		// operator asked for it and a silent fallback would be confusing.
		return "", fmt.Errorf("env file %s not found", p)
	}

	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), DefaultEnvFile))
	}
	candidates = append(candidates, DefaultEnvFile)

	for _, c := range candidates {
		ok, err := LoadEnvFile(c)
		if err != nil {
			return "", err
		}
		if ok {
			return c, nil
		}
	}
	return "", nil
}
