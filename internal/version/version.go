// Package version holds build identification used in logs, the User-Agent
// header and /health.
package version

// Version is the semantic version of the relay.
const Version = "1.0.0"

// Name is the application name.
const Name = "google-drive-relay"

// UserAgent is sent to Google on every API call. Google asks API clients to
// identify themselves.
const UserAgent = Name + "/" + Version + " (Go)"
