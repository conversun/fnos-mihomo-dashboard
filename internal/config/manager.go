package config

import (
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

	applyFnOSOverrides(cfg)

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
// yaml as the mihomo config, then applies fnOS forced overrides (external-
// controller, profile, dns, tun, sniffer). The user's proxies / proxy-groups
// / rules / rule-providers / etc. from the subscription are preserved as-is.
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

	// Apply fnOS forced overrides — this is where the subscription's dns / tun /
	// sniffer / external-controller / profile are replaced with the fnOS gateway
	// defaults. User proxies / proxy-groups / rules / rule-providers are kept.
	applyFnOSOverrides(cfg)

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
// fnOS 旁路网关 scenario. These fields are owned by fnOS for stability +
// framework consistency and cannot be overridden by the subscription:
//
//   1. external-controller pinned to 127.0.0.1:19090 (dashboard reverse-proxy)
//   2. external-ui removed (dashboard serves MetaCubeXD at /clash/)
//   3. profile.store-selected + store-fake-ip = true (persist UI choices)
//   4. dns: full sidecar-gateway DNS stack from ../docs/mihomo.md
//   5. tun: gateway-grade TUN config; enable defaults to false (opt-in
//      via MetaCubeXD or direct yaml edit). 198.18.x must NOT be excluded.
//   6. sniffer: TLS/HTTP/QUIC; transparent-proxy rules need it to match
//
// What we explicitly DO NOT touch (the subscription owns these):
//   - proxies, proxy-groups, rules, rule-providers (business config)
//   - mixed-port / mode / log-level / ipv6 / allow-lan / bind-address
//   - any other field the subscription set
func applyFnOSOverrides(cfg map[string]any) {
	// 1. fnOS framework fields (NOT NEGOTIABLE)
	cfg["external-controller"] = "127.0.0.1:19090"
	delete(cfg, "external-ui")
	delete(cfg, "external-controller-tls")
	delete(cfg, "external-controller-unix")

	// 2. profile (persist user choices across reloads / restarts)
	cfg["profile"] = map[string]any{
		"store-selected": true,
		"store-fake-ip":  true,
	}

	// 3. DNS — full sidecar-gateway stack (see ../docs/mihomo.md §1, §3)
	cfg["dns"] = map[string]any{
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

	// 4. TUN — gateway-grade config. enable defaults to false (opt-in via
	//    MetaCubeXD or direct yaml edit). 198.18.x is intentionally NOT in
	//    inet4-route-exclude-address (fake-ip must be handled by TUN).
	cfg["tun"] = map[string]any{
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

	// 5. Sniffer — transparent-proxy rule matching needs this
	cfg["sniffer"] = map[string]any{
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
	return []map[string]any{
		{"key": "external-controller", "desc": "fnOS 反代用 127.0.0.1:19090 (强制)", "value": "127.0.0.1:19090"},
		{"key": "profile.store-selected / store-fake-ip", "desc": "持久化策略组选择 + fake-ip 池", "value": true},
		{"key": "dns", "desc": "旁路网关 DNS 全套 (国内 nameserver + fake-ip + 完整 fake-ip-filter, 不含被墙的 fallback)", "value": "managed"},
		{"key": "tun", "desc": "旁路网关 TUN 配置 (enable=true 默认, fnOS 安装时已 setcap 授权; 198.18.x 必由 TUN 接管)", "value": "managed"},
		{"key": "sniffer", "desc": "TLS/HTTP/QUIC Sniffer (透明代理规则匹配必需)", "value": "enabled"},
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

