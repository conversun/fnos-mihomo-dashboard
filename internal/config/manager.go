package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// OverrideSettings controls which fnOS-managed fields are forcibly written into config.yaml.
// Defaults keep the upstream behavior. Turning a switch off preserves the subscription/user value.
type OverrideSettings struct {
	ExternalController bool   `json:"external_controller"`
	Profile            bool   `json:"profile"`
	DNS                bool   `json:"dns"`
	TUN                bool   `json:"tun"`
	Sniffer            bool   `json:"sniffer"`
	ProfileYAML        string `json:"profile_yaml"`
	DNSYAML            string `json:"dns_yaml"`
	TUNYAML            string `json:"tun_yaml"`
	SnifferYAML        string `json:"sniffer_yaml"`
}

func DefaultOverrideSettings() OverrideSettings {
	return OverrideSettings{
		ExternalController: true,
		Profile:            true,
		DNS:                true,
		TUN:                true,
		Sniffer:            true,
		ProfileYAML:        mustYAML(defaultProfileConfig()),
		DNSYAML:            mustYAML(defaultDNSConfig()),
		TUNYAML:            mustYAML(defaultTUNConfig()),
		SnifferYAML:        mustYAML(defaultSnifferConfig()),
	}
}

func (m *Manager) overridesPath() string {
	return filepath.Join(filepath.Dir(m.Path), ".fnos-overrides.json")
}

// OverrideSettings returns saved override switches and editable YAML snippets.
// Missing files/fields use safe defaults.
func (m *Manager) OverrideSettings() (OverrideSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.overrideSettingsUnsafe()
}

func (m *Manager) overrideSettingsUnsafe() (OverrideSettings, error) {
	settings := DefaultOverrideSettings()
	b, err := os.ReadFile(m.overridesPath())
	if os.IsNotExist(err) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	if err := json.Unmarshal(b, &settings); err != nil {
		return DefaultOverrideSettings(), fmt.Errorf("parse override settings: %w", err)
	}
	return normalizeOverrideSettings(settings), nil
}

// SetOverrideSettings persists override switches and custom YAML snippets for future subscription saves/refreshes.
func (m *Manager) SetOverrideSettings(settings OverrideSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	settings = normalizeOverrideSettings(settings)
	if err := validateOverrideSettings(settings); err != nil {
		return err
	}
	b, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.overridesPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.overridesPath())
}

// ResetOverrideSettings removes custom settings so the built-in defaults are used again.
func (m *Manager) ResetOverrideSettings() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.Remove(m.overridesPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func normalizeOverrideSettings(settings OverrideSettings) OverrideSettings {
	defaults := DefaultOverrideSettings()
	if strings.TrimSpace(settings.ProfileYAML) == "" {
		settings.ProfileYAML = defaults.ProfileYAML
	}
	if strings.TrimSpace(settings.DNSYAML) == "" {
		settings.DNSYAML = defaults.DNSYAML
	}
	if strings.TrimSpace(settings.TUNYAML) == "" {
		settings.TUNYAML = defaults.TUNYAML
	}
	if strings.TrimSpace(settings.SnifferYAML) == "" {
		settings.SnifferYAML = defaults.SnifferYAML
	}
	return settings
}

func validateOverrideSettings(settings OverrideSettings) error {
	if settings.Profile {
		if _, err := parseYAMLMap(settings.ProfileYAML, "profile"); err != nil {
			return err
		}
	}
	if settings.DNS {
		if _, err := parseYAMLMap(settings.DNSYAML, "dns"); err != nil {
			return err
		}
	}
	if settings.TUN {
		if _, err := parseYAMLMap(settings.TUNYAML, "tun"); err != nil {
			return err
		}
	}
	if settings.Sniffer {
		if _, err := parseYAMLMap(settings.SnifferYAML, "sniffer"); err != nil {
			return err
		}
	}
	return nil
}

func parseYAMLMap(raw, name string) (map[string]any, error) {
	var out map[string]any
	if err := yaml.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("parse %s yaml: %w", name, err)
	}
	if out == nil {
		return nil, fmt.Errorf("%s yaml cannot be empty", name)
	}
	return out, nil
}

func mustYAML(v any) string {
	b, err := yaml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b)) + "\n"
}

func (m *Manager) applyFnOSOverrides(cfg map[string]any) error {
	settings, err := m.overrideSettingsUnsafe()
	if err != nil {
		settings = DefaultOverrideSettings()
	}
	return applyFnOSOverrides(cfg, settings)
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

	if err := m.applyFnOSOverrides(cfg); err != nil {
		return err
	}

	return m.writeUnsafe(cfg)
}

// subURLPath returns the sidecar file that stores the current subscription URL.
// We keep it separate from config.yaml because the proxy-provider now uses
// type: file (mihomo doesn't need to know the original remote URL).
func (m *Manager) subURLPath() string {
	return filepath.Join(filepath.Dir(m.Path), ".fnos-subscription.url")
}

// GetSubscription returns the current fnos-subscription URL (or empty string).
func (m *Manager) GetSubscription() (string, error) {
	b, err := os.ReadFile(m.subURLPath())
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// SetSubscriptionFromURL persists the URL and writes the entire subscription
// yaml as the mihomo config, then applies enabled fnOS overrides. User proxies /
// proxy-groups / rules / rule-providers / etc. from the subscription are preserved as-is.
func (m *Manager) SetSubscriptionFromURL(url string, fullYAML []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cfg map[string]any
	if err := yaml.Unmarshal(fullYAML, &cfg); err != nil {
		return fmt.Errorf("parse subscription yaml: %w", err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	if proxies, _ := cfg["proxies"].([]any); len(proxies) == 0 {
		return fmt.Errorf("subscription yaml has no proxies (empty / not a Clash subscription)")
	}

	if err := m.applyFnOSOverrides(cfg); err != nil {
		return err
	}

	if err := os.WriteFile(m.subURLPath(), []byte(url), 0o644); err != nil {
		return err
	}
	return m.writeUnsafe(cfg)
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

// applyFnOSOverrides hardens a user-supplied subscription config for the
// fnOS 旁路网关 scenario. Enabled fields are owned by fnOS for stability +
// framework consistency; disabled fields preserve subscription/user values.
func applyFnOSOverrides(cfg map[string]any, settings OverrideSettings) error {
	settings = normalizeOverrideSettings(settings)
	if err := validateOverrideSettings(settings); err != nil {
		return err
	}

	if settings.ExternalController {
		cfg["external-controller"] = "127.0.0.1:19090"
		delete(cfg, "external-ui")
		delete(cfg, "external-controller-tls")
		delete(cfg, "external-controller-unix")
	}

	if settings.Profile {
		profile, err := parseYAMLMap(settings.ProfileYAML, "profile")
		if err != nil {
			return err
		}
		cfg["profile"] = profile
	}

	if settings.DNS {
		dns, err := parseYAMLMap(settings.DNSYAML, "dns")
		if err != nil {
			return err
		}
		cfg["dns"] = dns
	}

	if settings.TUN {
		tun, err := parseYAMLMap(settings.TUNYAML, "tun")
		if err != nil {
			return err
		}
		cfg["tun"] = tun
	}

	if settings.Sniffer {
		sniffer, err := parseYAMLMap(settings.SnifferYAML, "sniffer")
		if err != nil {
			return err
		}
		cfg["sniffer"] = sniffer
	}
	return nil
}

func defaultProfileConfig() map[string]any {
	return map[string]any{
		"store-selected": true,
		"store-fake-ip":  true,
	}
}

func defaultDNSConfig() map[string]any {
	return map[string]any{
		"enable":                          true,
		"cache-algorithm":                 "arc",
		"prefer-h3":                       false,
		"listen":                          "0.0.0.0:1053",
		"ipv6":                            true,
		"respect-rules":                   true,
		"use-hosts":                       true,
		"use-system-hosts":                true,
		"enhanced-mode":                   "fake-ip",
		"fake-ip-range":                   "198.18.0.1/16",
		"fake-ip-filter-mode":             "blacklist",
		"default-nameserver":              []any{"223.5.5.5", "119.29.29.29"},
		"nameserver":                      []any{"223.5.5.5", "119.29.29.29"},
		"proxy-server-nameserver":         []any{"223.5.5.5", "119.29.29.29"},
		"direct-nameserver":               []any{"system"},
		"direct-nameserver-follow-policy": true,
		"fake-ip-filter": []any{
			"*.lan", "*.local", "localhost.ptlogin2.qq.com",
			"time.windows.com", "time.apple.com",
			"+.pool.ntp.org", "+.stun.*",
			"dns.msftncsi.com", "+.msftconnecttest.com", "+.msftncsi.com",
			"+.srv.nintendo.net", "+.stun.playstation.net",
			"xbox.*.microsoft.com", "+.xboxlive.com",
			"+.turn.twilio.com", "+.stun.twilio.com", "stun.syncthing.net",
			"+.logon.battlenet.com.cn", "+.logon.battle.net", "+.blzstatic.cn",
			"network-test.debian.org", "detectportal.firefox.com", "resolver1.opendns.com",
			"ntp.*.com", "time.*.com", "time.*.gov", "time.*.edu.cn", "+.ntp.org.cn",
		},
	}
}

func defaultTUNConfig() map[string]any {
	return map[string]any{
		"enable":                true,
		"device":                "Meta",
		"stack":                 "mixed",
		"auto-route":            true,
		"auto-redirect":         false,
		"auto-detect-interface": true,
		"strict-route":          false,
		"mtu":                   1500,
		"dns-hijack":            []any{"any:53"},
		"inet4-route-exclude-address": []any{
			"192.168.0.0/16",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"169.254.0.0/16",
		},
	}
}

func defaultSnifferConfig() map[string]any {
	return map[string]any{
		"enable": true,
		"sniff": map[string]any{
			"TLS":  map[string]any{"ports": []any{443, 8443}},
			"HTTP": map[string]any{"ports": []any{80, 8080, 8880}, "override-destination": true},
			"QUIC": map[string]any{"ports": []any{443, 8443}},
		},
		"parse-pure-ip":        true,
		"override-destination": true,
		"skip-domain":          []any{"+.apple.com", "+.icloud.com"},
	}
}

// AppliedOverrides returns a human-readable list of overrides applied to the config.
func (m *Manager) AppliedOverrides() []map[string]any {
	settings, err := m.OverrideSettings()
	if err != nil {
		settings = DefaultOverrideSettings()
	}
	state := func(enabled bool) string {
		if enabled {
			return "managed"
		}
		return "preserved"
	}
	return []map[string]any{
		{"key": "external-controller", "desc": "fnOS 反代用 127.0.0.1:19090；关闭后保留订阅/用户值，可能影响面板连接", "value": state(settings.ExternalController), "enabled": settings.ExternalController},
		{"key": "profile", "desc": "持久化策略组选择 + fake-ip 池；关闭后保留订阅/用户 profile", "value": state(settings.Profile), "enabled": settings.Profile},
		{"key": "dns", "desc": "旁路网关 DNS 配置；开启时使用下方可编辑 YAML", "value": state(settings.DNS), "enabled": settings.DNS},
		{"key": "tun", "desc": "旁路网关 TUN 配置；开启时使用下方可编辑 YAML", "value": state(settings.TUN), "enabled": settings.TUN},
		{"key": "sniffer", "desc": "TLS/HTTP/QUIC Sniffer；开启时使用下方可编辑 YAML", "value": state(settings.Sniffer), "enabled": settings.Sniffer},
	}
}

// Backup copies config.yaml to config.yaml.bak (atomic). Returns path of backup.
func (m *Manager) Backup() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := os.ReadFile(m.Path)
	if err != nil {
		return "", err
	}
	bak := m.Path + ".bak"
	tmp := bak + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, bak); err != nil {
		return "", err
	}
	return bak, nil
}

// RestoreFromBackup overwrites config.yaml with config.yaml.bak.
func (m *Manager) RestoreFromBackup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	bak := m.Path + ".bak"
	data, err := os.ReadFile(bak)
	if err != nil {
		return err
	}
	return os.WriteFile(m.Path, data, 0o644)
}

// HasBackup reports whether a previous backup file exists.
func (m *Manager) HasBackup() bool {
	_, err := os.Stat(m.Path + ".bak")
	return err == nil
}

// WriteMinimalConfig writes a sane starter config.yaml when none exists.
// Subscription URL is not yet known — user will add it via the dashboard.
func (m *Manager) WriteMinimalConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := map[string]any{
		"mixed-port":   7890,
		"allow-lan":    true,
		"bind-address": "*",
		"mode":         "rule",
		"log-level":    "info",
		"ipv6":         false,
		"secret":       "",
		"proxies":      []any{},
		"proxy-groups": []any{
			map[string]any{
				"name":    "PROXY",
				"type":    "select",
				"proxies": []any{"DIRECT"},
			},
		},
		"rules": []any{"MATCH,PROXY"},
	}
	if err := m.applyFnOSOverrides(cfg); err != nil {
		return err
	}
	return m.writeUnsafe(cfg)
}

// Exists reports whether the config file is present on disk.
func (m *Manager) Exists() bool {
	_, err := os.Stat(m.Path)
	return err == nil
}
