package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A configured subscription turns config.yaml into a credential store: every
// node carries a password or UUID. The config view must stay useful without
// handing those out.
func TestRedactedYAMLMasksCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := `secret: CONTROLLER_SECRET
proxies:
  - name: node-1
    type: ss
    server: example.com
    port: 8388
    password: NODE_PASSWORD
  - name: node-2
    type: vmess
    server: example.net
    uuid: 11111111-2222-3333-4444-555555555555
proxy-providers:
  fnos-subscription:
    type: http
    url: https://airline.example.com/sub?token=SUBSCRIPTION_TOKEN
    path: /vol1/providers/fnos.yaml
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := New(path).RedactedYAML()
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	for _, secret := range []string{
		"NODE_PASSWORD",
		"11111111-2222-3333-4444-555555555555",
		"CONTROLLER_SECRET",
		"SUBSCRIPTION_TOKEN",
	} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted config still contains %q:\n%s", secret, got)
		}
	}

	// Structure must survive so the view is still useful for debugging.
	for _, keep := range []string{"node-1", "node-2", "example.com", "airline.example.com"} {
		if !strings.Contains(got, keep) {
			t.Errorf("redacted config lost non-secret detail %q", keep)
		}
	}
	// A local path is not a secret and helps diagnosis.
	if !strings.Contains(got, "/vol1/providers/fnos.yaml") {
		t.Error("local provider path should be preserved")
	}
}

func TestMaskSubscriptionURL(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"https://air.example.com/s?t=A": "https://air.example.com/" + redactedMask,
		"http://u:p@air.example.com/x":  "http://air.example.com/" + redactedMask,
		"garbage":                       redactedMask,
	}
	for in, want := range cases {
		if got := MaskSubscriptionURL(in); got != want {
			t.Errorf("MaskSubscriptionURL(%q) = %q, want %q", in, got, want)
		}
	}
	// The token itself must never survive masking.
	if got := MaskSubscriptionURL("https://air.example.com/sub?token=SEKRET"); strings.Contains(got, "SEKRET") {
		t.Errorf("masked URL still leaks the token: %s", got)
	}
}

// Existing installs kept 0644 from an older build, leaving node passwords and
// the controller secret world-readable. Startup must tighten them; the atomic
// writer alone only covers files it creates.
func TestTightenExistingPerms(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "config.yaml")

	files := []string{
		confPath,
		confPath + ".bak",
		filepath.Join(dir, ".fnos-subscription.url"),
		filepath.Join(dir, ".fnos-overrides.json"),
		filepath.Join(dir, ".fnos-admin-token"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("secret"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	New(confPath).TightenExistingPerms()

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %v, want 0600", filepath.Base(f), perm)
		}
	}
}

// A symlink planted at one of these paths must not be chased: the service runs
// as root, so following it would chmod an arbitrary file.
func TestTightenExistingPermsIgnoresSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(victim, confPath); err != nil {
		t.Fatal(err)
	}

	New(confPath).TightenExistingPerms()

	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("symlink target was chmodded to %v; must be left alone", perm)
	}
}
