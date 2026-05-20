package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Manager safely reads/writes mihomo's config.yaml, treating proxy-providers as the
// "subscription" surface that we mutate, while preserving all other user-managed fields.
type Manager struct {
	Path string
	mu   sync.Mutex
}

func New(path string) *Manager {
	return &Manager{Path: path}
}

// Read returns the raw config as a map (preserving order via yaml.Node would need more work,
// but for our limited mutation surface a map is fine).
func (m *Manager) Read() (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readUnsafe()
}

func (m *Manager) readUnsafe() (map[string]any, error) {
	b, err := os.ReadFile(m.Path)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", m.Path, err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// SetSubscription replaces the `proxy-providers.fnos-subscription` entry with the given URL.
// All other proxy-providers (if any) are preserved. Also ensures the default proxy-group
// includes this provider via `use:`.
func (m *Manager) SetSubscription(url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, err := m.readUnsafe()
	if err != nil {
		return err
	}

	providers, _ := cfg["proxy-providers"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
	}

	dir := filepath.Dir(m.Path)
	providerPath := filepath.Join(dir, "providers", "fnos-subscription.yaml")

	providers["fnos-subscription"] = map[string]any{
		"type":     "http",
		"url":      url,
		"interval": 86400, // 24h
		"path":     providerPath,
		"health-check": map[string]any{
			"enable":   true,
			"url":      "http://www.gstatic.com/generate_204",
			"interval": 300,
		},
	}
	cfg["proxy-providers"] = providers

	// Ensure default PROXY group uses this provider
	groups, _ := cfg["proxy-groups"].([]any)
	hasFnosGroup := false
	for i, g := range groups {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := gm["name"].(string); name == "PROXY" {
			use, _ := gm["use"].([]any)
			has := false
			for _, u := range use {
				if s, _ := u.(string); s == "fnos-subscription" {
					has = true
					break
				}
			}
			if !has {
				use = append(use, "fnos-subscription")
				gm["use"] = use
			}
			groups[i] = gm
			hasFnosGroup = true
			break
		}
	}
	if !hasFnosGroup {
		groups = append([]any{map[string]any{
			"name":    "PROXY",
			"type":    "select",
			"use":     []any{"fnos-subscription"},
			"proxies": []any{"DIRECT"},
		}}, groups...)
	}
	cfg["proxy-groups"] = groups

	// Ensure at least one rule exists (MATCH,PROXY)
	if rules, _ := cfg["rules"].([]any); len(rules) == 0 {
		cfg["rules"] = []any{"MATCH,PROXY"}
	}

	return m.writeUnsafe(cfg)
}

// GetSubscription returns the current fnos-subscription URL (or empty string).
func (m *Manager) GetSubscription() (string, error) {
	cfg, err := m.Read()
	if err != nil {
		return "", err
	}
	providers, _ := cfg["proxy-providers"].(map[string]any)
	sub, _ := providers["fnos-subscription"].(map[string]any)
	url, _ := sub["url"].(string)
	return url, nil
}

func (m *Manager) writeUnsafe(cfg map[string]any) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// Atomic write
	tmp := m.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.Path)
}
