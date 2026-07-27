package config

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// secretKeys are config fields whose values are credentials. A subscription
// brings these in per-proxy, so the raw config is effectively a credential
// store: node passwords, UUIDs, and the controller secret.
//
// The dashboard's config view is useful for debugging, so the structure is
// preserved and only the values are masked — rather than dropping the endpoint
// or hiding the whole proxies section.
var secretKeys = map[string]bool{
	"password":       true,
	"uuid":           true,
	"secret":         true,
	"psk":            true,
	"auth":           true,
	"token":          true,
	"private-key":    true,
	"public-key":     true,
	"pre-shared-key": true,
	"ws-headers":     true,
	"servername":     false, // hostname, not a secret
}

// urlKeys hold values that may embed a subscription token in the query string.
var urlKeys = map[string]bool{
	"url":  true,
	"path": false, // local filesystem path, safe to show
}

const redactedMask = "***REDACTED***"

// RedactedYAML returns the config with credential values masked, ready to show
// in the UI. Returns an error only when the config cannot be parsed.
func (m *Manager) RedactedYAML() ([]byte, error) {
	cfg, err := m.Read()
	if err != nil {
		return nil, err
	}
	redactTree(cfg)
	return yaml.Marshal(cfg)
}

// redactTree walks the config and masks secret values in place.
func redactTree(node any) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			lk := strings.ToLower(k)
			if secretKeys[lk] {
				v[k] = redactedMask
				continue
			}
			if urlKeys[lk] {
				if s, ok := val.(string); ok {
					v[k] = maskURL(s)
					continue
				}
			}
			redactTree(val)
		}
	case []any:
		for _, item := range v {
			redactTree(item)
		}
	}
}

// maskURL keeps the scheme and host (useful for diagnosis) but drops the path,
// query and any userinfo, which is where subscription tokens live.
func maskURL(raw string) string {
	if raw == "" {
		return raw
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return redactedMask
	}
	host, _, _ := strings.Cut(rest, "/")
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:] // strip embedded credentials
	}
	if host == "" {
		return redactedMask
	}
	return scheme + "://" + host + "/" + redactedMask
}

// MaskSubscriptionURL renders a subscription URL safe for display: the host is
// shown so a user can tell which provider is configured, the token is not.
func MaskSubscriptionURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return maskURL(raw)
}
