package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// A minimal but valid Clash subscription. Like most real ones it says nothing
// about allow-lan, leaving mihomo's built-in default (false) to win.
const subscriptionWithoutAllowLAN = `mixed-port: 7890
mode: rule
proxies:
  - name: node-1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: NODE_PASSWORD
proxy-groups:
  - name: PROXY
    type: select
    proxies: [node-1]
rules:
  - MATCH,PROXY
`

// Some airlines ship allow-lan explicitly off, which is the literal shape the
// reporter of #272 ended up with.
const subscriptionWithAllowLANFalse = `mixed-port: 7890
mode: rule
allow-lan: false
bind-address: 127.0.0.1
proxies:
  - name: node-1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: NODE_PASSWORD
proxy-groups:
  - name: PROXY
    type: select
    proxies: [node-1]
rules:
  - MATCH,PROXY
`

func unmarshalConfig(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("rendered config is not valid yaml: %v", err)
	}
	return cfg
}

// overridesWire encodes settings the way .fnos-overrides.json stores them and
// the way GET /api/overrides hands them to the frontend, so a test can pin both
// the value and the JSON name the UI toggles.
func overridesWire(t *testing.T, settings OverrideSettings) map[string]any {
	t.Helper()
	b, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal override settings: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode override settings: %v", err)
	}
	return out
}

// Issue #272: the fnOS package seeds allow-lan so LAN devices can use the
// proxy, but saving a subscription replaces the whole config map and only a
// fixed set of keys is re-applied afterwards. A subscription that says nothing
// about allow-lan must not silently take LAN access away.
func TestRenderSubscriptionKeepsAllowLANWhenSubscriptionOmitsIt(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.yaml"))

	out, err := m.RenderSubscription([]byte(subscriptionWithoutAllowLAN))
	if err != nil {
		t.Fatal(err)
	}

	cfg := unmarshalConfig(t, out)
	if cfg["allow-lan"] != true {
		t.Errorf("allow-lan = %#v, want true; LAN devices lose the proxy otherwise", cfg["allow-lan"])
	}
	// allow-lan without a wildcard bind only listens on loopback, so the pair
	// has to move together.
	if cfg["bind-address"] != "*" {
		t.Errorf("bind-address = %#v, want \"*\"", cfg["bind-address"])
	}
}

// The reporter's exact scenario: the subscription itself carries allow-lan:
// false. An enabled fnOS override outranks it, same as it does for dns or tun.
func TestRenderSubscriptionOverridesExplicitAllowLANFalse(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.yaml"))

	out, err := m.RenderSubscription([]byte(subscriptionWithAllowLANFalse))
	if err != nil {
		t.Fatal(err)
	}

	cfg := unmarshalConfig(t, out)
	if cfg["allow-lan"] != true {
		t.Errorf("allow-lan = %#v, want true; the subscription value must not win", cfg["allow-lan"])
	}
	if cfg["bind-address"] != "*" {
		t.Errorf("bind-address = %#v, want \"*\"", cfg["bind-address"])
	}
}

// LAN access is what the fnOS package advertises, so the switch ships on. The
// JSON name is part of the contract: the frontend toggle binds to it directly.
func TestDefaultOverrideSettingsEnablesAllowLAN(t *testing.T) {
	wire := overridesWire(t, DefaultOverrideSettings())

	if wire["allow_lan"] != true {
		t.Errorf("default allow_lan = %#v, want true", wire["allow_lan"])
	}
}

// Installs predating this switch have a .fnos-overrides.json with no allow_lan
// key. Saved settings are decoded OVER the defaults, so those installs inherit
// true — restoring the LAN access they had before their first subscription
// refresh broke it.
func TestLegacyOverridesFileInheritsAllowLANDefault(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"external_controller":true,"profile":true,"dns":true,"tun":true,"sniffer":true,` +
		`"profile_yaml":"store-selected: true\n","dns_yaml":"enable: true\n",` +
		`"tun_yaml":"enable: true\n","sniffer_yaml":"enable: true\n"}`
	if err := os.WriteFile(filepath.Join(dir, ".fnos-overrides.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	settings, err := New(filepath.Join(dir, "config.yaml")).OverrideSettings()
	if err != nil {
		t.Fatal(err)
	}

	wire := overridesWire(t, settings)
	if wire["allow_lan"] != true {
		t.Errorf("legacy install allow_lan = %#v, want true", wire["allow_lan"])
	}
}

// Off means preserved, exactly like every other switch: whatever the
// subscription or the user set survives untouched — including the key being
// absent, which is how mihomo falls back to its own default.
func TestApplyFnOSOverridesPreservesAllowLANWhenDisabled(t *testing.T) {
	// overrideSettingsUnsafe decodes the saved file over the defaults; do the
	// same, so the test turns the switch off the way production does.
	settings := DefaultOverrideSettings()
	if err := json.Unmarshal([]byte(`{"allow_lan":false}`), &settings); err != nil {
		t.Fatal(err)
	}

	absent := map[string]any{}
	if err := applyFnOSOverrides(absent, settings); err != nil {
		t.Fatal(err)
	}
	if v, ok := absent["allow-lan"]; ok {
		t.Errorf("allow-lan was written as %#v while the switch is off; it must stay absent", v)
	}
	if v, ok := absent["bind-address"]; ok {
		t.Errorf("bind-address was written as %#v while the switch is off; it must stay absent", v)
	}

	userSet := map[string]any{"allow-lan": false, "bind-address": "127.0.0.1"}
	if err := applyFnOSOverrides(userSet, settings); err != nil {
		t.Fatal(err)
	}
	if userSet["allow-lan"] != false {
		t.Errorf("allow-lan = %#v, want the user's false", userSet["allow-lan"])
	}
	if userSet["bind-address"] != "127.0.0.1" {
		t.Errorf("bind-address = %#v, want the user's 127.0.0.1", userSet["bind-address"])
	}
}
