package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultTokenEndpoint is Google's OAuth 2.0 token endpoint.
const DefaultTokenEndpoint = "https://oauth2.googleapis.com/token"

// AuthMode describes how the relay authenticates to Google Drive.
type AuthMode string

const (
	// AuthModeRefresh is the preferred, self-healing configuration: the relay
	// can mint new access tokens from the refresh token.
	AuthModeRefresh AuthMode = "refresh"
	// AuthModeAccessOnly is for temporary testing: a single access token that
	// the relay cannot renew once it expires.
	AuthModeAccessOnly AuthMode = "access-only"
	// AuthModeNone means no credentials are configured. The server still
	// starts so /health and the web UI are reachable, but Drive calls fail
	// with a clear authentication error.
	AuthModeNone AuthMode = "none"
)

// Google holds the OAuth credentials and token endpoint settings.
type Google struct {
	AccessToken   Secret
	RefreshToken  Secret
	ClientID      Secret
	ClientSecret  Secret
	TokenEndpoint string
	RefreshSkew   time.Duration
	TokenTimeout  time.Duration
}

// Mode reports the active authentication mode.
func (g Google) Mode() AuthMode {
	hasRefresh := !g.RefreshToken.IsZero() && !g.ClientID.IsZero() && !g.ClientSecret.IsZero()
	hasAccess := !g.AccessToken.IsZero()

	switch {
	case hasRefresh:
		return AuthModeRefresh
	case hasAccess:
		return AuthModeAccessOnly
	default:
		return AuthModeNone
	}
}

// CanRefresh reports whether new access tokens can be minted.
func (g Google) CanRefresh() bool { return g.Mode() == AuthModeRefresh }

// MissingRefreshParts lists the refresh-mode variables that are still empty,
// for actionable diagnostics.
func (g Google) MissingRefreshParts() []string {
	var missing []string
	if g.RefreshToken.IsZero() {
		missing = append(missing, "GOOGLE_REFRESH_TOKEN")
	}
	if g.ClientID.IsZero() {
		missing = append(missing, "GOOGLE_CLIENT_ID")
	}
	if g.ClientSecret.IsZero() {
		missing = append(missing, "GOOGLE_CLIENT_SECRET")
	}
	return missing
}

// String renders the credential set with every secret redacted.
func (g Google) String() string {
	return fmt.Sprintf("google{mode=%s access_token=%s refresh_token=%s client_id=%s client_secret=%s token_endpoint=%s}",
		g.Mode(),
		g.AccessToken.String(),
		g.RefreshToken.String(),
		g.ClientID.String(),
		g.ClientSecret.String(),
		g.TokenEndpoint,
	)
}

// Server holds HTTP server settings.
type Server struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// Security holds access control and request-limiting settings.
type Security struct {
	APIKey              Secret
	RequireAPIKey       bool
	SessionTTL          time.Duration
	RateLimitEnabled    bool
	RateLimitRPS        float64
	RateLimitBurst      int
	TrustProxy          bool
	AllowedOrigins      []string
	MaxConcurrentStream int
}

// Transfer holds streaming limits.
type Transfer struct {
	MaxFileSize int64
	Bandwidth   int64 // bytes per second, 0 = unlimited
	BufferSize  int
}

// Web holds web interface settings.
type Web struct {
	Enabled bool
}

// Config is the fully resolved application configuration.
type Config struct {
	Google    Google
	Server    Server
	Security  Security
	Transfer  Transfer
	Web       Web
	LogLevel  string
	LogFormat string

	// EnvFile is the env file that was loaded, if any (informational).
	EnvFile string
}

// Load reads the configuration from the process environment, applying
// defaults and validating the result.
func Load() (*Config, error) {
	var err error
	cfg := &Config{
		Server: Server{
			Addr:              getString("RELAY_ADDR", ":8080"),
			ReadHeaderTimeout: getDuration("RELAY_READ_HEADER_TIMEOUT", 15*time.Second),
			IdleTimeout:       getDuration("RELAY_IDLE_TIMEOUT", 120*time.Second),
			ShutdownTimeout:   getDuration("RELAY_SHUTDOWN_TIMEOUT", 15*time.Second),
		},
		Security: Security{
			APIKey:              Secret(getString("RELAY_API_KEY", "")),
			SessionTTL:          getDuration("RELAY_SESSION_TTL", 12*time.Hour),
			RateLimitEnabled:    getBool("RELAY_RATE_LIMIT_ENABLED", true),
			RateLimitRPS:        getFloat("RELAY_RATE_LIMIT_RPS", 10),
			RateLimitBurst:      getInt("RELAY_RATE_LIMIT_BURST", 30),
			TrustProxy:          getBool("RELAY_TRUST_PROXY", false),
			AllowedOrigins:      getList("RELAY_ALLOWED_ORIGINS"),
			MaxConcurrentStream: getInt("RELAY_MAX_CONCURRENT_STREAMS", 0),
		},
		Transfer: Transfer{
			BufferSize: getInt("RELAY_STREAM_BUFFER_SIZE", 64*1024),
		},
		Web: Web{
			Enabled: getBool("RELAY_WEB_UI_ENABLED", true),
		},
		LogLevel:  getString("RELAY_LOG_LEVEL", "info"),
		LogFormat: getString("RELAY_LOG_FORMAT", "text"),
	}

	cfg.Google = Google{
		AccessToken:   Secret(getString("GOOGLE_ACCESS_TOKEN", "")),
		RefreshToken:  Secret(getString("GOOGLE_REFRESH_TOKEN", "")),
		ClientID:      Secret(getString("GOOGLE_CLIENT_ID", "")),
		ClientSecret:  Secret(getString("GOOGLE_CLIENT_SECRET", "")),
		TokenEndpoint: getString("GOOGLE_TOKEN_ENDPOINT", DefaultTokenEndpoint),
		RefreshSkew:   getDuration("GOOGLE_REFRESH_SKEW", 2*time.Minute),
		TokenTimeout:  getDuration("GOOGLE_TOKEN_TIMEOUT", 20*time.Second),
	}

	// RELAY_REQUIRE_API_KEY defaults to "true when a key is configured".
	if cfg.Security.APIKey.IsZero() {
		cfg.Security.RequireAPIKey = getBool("RELAY_REQUIRE_API_KEY", false)
	} else {
		cfg.Security.RequireAPIKey = getBool("RELAY_REQUIRE_API_KEY", true)
	}

	if cfg.Transfer.MaxFileSize, err = parseSize(getString("RELAY_MAX_FILE_SIZE", "0")); err != nil {
		return nil, fmt.Errorf("RELAY_MAX_FILE_SIZE: %w", err)
	}
	if cfg.Transfer.Bandwidth, err = parseSize(getString("RELAY_BANDWIDTH_LIMIT", "0")); err != nil {
		return nil, fmt.Errorf("RELAY_BANDWIDTH_LIMIT: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.Server.Addr) == "" {
		return fmt.Errorf("RELAY_ADDR must not be empty")
	}
	if c.Server.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("RELAY_READ_HEADER_TIMEOUT must be positive")
	}
	if c.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("RELAY_SHUTDOWN_TIMEOUT must be positive")
	}
	if c.Google.TokenTimeout <= 0 {
		return fmt.Errorf("GOOGLE_TOKEN_TIMEOUT must be positive")
	}
	if c.Google.RefreshSkew < 0 {
		return fmt.Errorf("GOOGLE_REFRESH_SKEW must not be negative")
	}
	if c.Transfer.BufferSize < 4096 || c.Transfer.BufferSize > 1024*1024 {
		return fmt.Errorf("RELAY_STREAM_BUFFER_SIZE must be between 4096 and 1048576, got %d", c.Transfer.BufferSize)
	}
	if c.Transfer.MaxFileSize < 0 {
		return fmt.Errorf("RELAY_MAX_FILE_SIZE must not be negative")
	}
	if c.Transfer.Bandwidth < 0 {
		return fmt.Errorf("RELAY_BANDWIDTH_LIMIT must not be negative")
	}
	if c.Security.RateLimitRPS < 0 {
		return fmt.Errorf("RELAY_RATE_LIMIT_RPS must not be negative")
	}
	if c.Security.RateLimitBurst < 0 {
		return fmt.Errorf("RELAY_RATE_LIMIT_BURST must not be negative")
	}
	if c.Security.MaxConcurrentStream < 0 {
		return fmt.Errorf("RELAY_MAX_CONCURRENT_STREAMS must not be negative")
	}
	if c.Security.SessionTTL <= 0 {
		return fmt.Errorf("RELAY_SESSION_TTL must be positive")
	}
	if !validTokenEndpoint(c.Google.TokenEndpoint) {
		return fmt.Errorf("GOOGLE_TOKEN_ENDPOINT must be an https URL, got %q", c.Google.TokenEndpoint)
	}

	// Refresh mode is all-or-nothing: a partial configuration is almost
	// always a mistake and would silently degrade to access-only mode.
	partial := c.Google
	missing := partial.MissingRefreshParts()
	if len(missing) > 0 && len(missing) < 3 {
		return fmt.Errorf(
			"incomplete refresh configuration: %s set but %s missing; "+
				"set all four or leave refresh mode unconfigured",
			strings.Join(setRefreshParts(partial), ", "),
			strings.Join(missing, ", "))
	}

	switch strings.ToLower(c.LogFormat) {
	case "text", "json":
	default:
		return fmt.Errorf("RELAY_LOG_FORMAT must be text or json, got %q", c.LogFormat)
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("RELAY_LOG_LEVEL must be debug, info, warn or error, got %q", c.LogLevel)
	}
	return nil
}

func setRefreshParts(g Google) []string {
	var set []string
	if !g.RefreshToken.IsZero() {
		set = append(set, "GOOGLE_REFRESH_TOKEN")
	}
	if !g.ClientID.IsZero() {
		set = append(set, "GOOGLE_CLIENT_ID")
	}
	if !g.ClientSecret.IsZero() {
		set = append(set, "GOOGLE_CLIENT_SECRET")
	}
	return set
}

func validTokenEndpoint(u string) bool {
	u = strings.TrimSpace(u)
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://127.0.0.1") || strings.HasPrefix(u, "http://localhost")
}

// Redacted returns a copy of the configuration safe to log.
func (c *Config) Redacted() map[string]any {
	return map[string]any{
		"auth_mode":          string(c.Google.Mode()),
		"access_token":       c.Google.AccessToken.String(),
		"refresh_token":      c.Google.RefreshToken.String(),
		"client_id":          c.Google.ClientID.String(),
		"client_secret":      c.Google.ClientSecret.String(),
		"token_endpoint":     c.Google.TokenEndpoint,
		"addr":               c.Server.Addr,
		"api_key_required":   c.Security.RequireAPIKey,
		"rate_limit_enabled": c.Security.RateLimitEnabled,
		"rate_limit_rps":     c.Security.RateLimitRPS,
		"rate_limit_burst":   c.Security.RateLimitBurst, "trust_proxy": c.Security.TrustProxy,
		"max_file_size":      c.Transfer.MaxFileSize,
		"bandwidth_limit":    c.Transfer.Bandwidth,
		"stream_buffer_size": c.Transfer.BufferSize,
		"max_concurrent":     c.Security.MaxConcurrentStream,
		"web_ui_enabled":     c.Web.Enabled,
		"log_level":          c.LogLevel,
		"log_format":         c.LogFormat,
	}
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

func getString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func getBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func getInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func getFloat(key string, def float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return def
	}
	return f
}

func getDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return d
}

func getList(key string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseSize parses "0", "unlimited", or a byte count with an optional
// KB/MB/GB/TB (or KiB/MiB/GiB/TiB) suffix. Bare suffixes use 1024-based
// multiples, matching what operators expect from a file-size limit.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "unlimited" || s == "none" {
		return 0, nil
	}
	mult := int64(1)
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40},
		{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"tb", 1 << 40},
		{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"t", 1 << 40},
		{"b", 1},
	}
	for _, sfx := range suffixes {
		if strings.HasSuffix(s, sfx.suffix) {
			mult = sfx.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, sfx.suffix))
			break
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("size must not be negative")
	}
	return int64(n * float64(mult)), nil
}
