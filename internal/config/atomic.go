package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// configPerm is used for every file that can carry secrets: config.yaml holds
// airline node passwords/UUIDs and the controller secret, and the subscription
// sidecar holds the subscription token — usually the most reusable credential
// in the whole system. The service runs as root, so 0644 would expose them to
// every local account.
const configPerm = 0o600

// writeFileAtomic writes data to path via a temp file in the SAME directory,
// fsyncs it, then renames over the target. The rename is atomic within a
// filesystem, so a reader never observes a partially written file and a crash
// mid-write leaves the previous content intact.
//
// os.WriteFile cannot give this guarantee: it truncates the target first, so a
// concurrent reader can see an empty or half-written file (the mechanism behind
// the unlocked-read race on the subscription sidecar).
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	// Any failure past this point must not leave the temp file behind.
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()

	if err := f.Chmod(configPerm); err != nil {
		f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	// Durability before the rename, otherwise a crash can leave the renamed
	// file present but empty.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	tmp = "" // renamed away; nothing to clean up
	return nil
}

// ReadRaw returns the current config bytes. Callers use it to snapshot state
// before a mutation so they can restore it precisely, rather than relying on a
// shared .bak file that a concurrent request can overwrite.
func (m *Manager) ReadRaw() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.ReadFile(m.Path)
}

// WriteRawAtomic replaces config.yaml with exactly these bytes.
func (m *Manager) WriteRawAtomic(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return writeFileAtomic(m.Path, data)
}

// WriteSubscriptionURLAtomic commits the subscription URL sidecar.
//
// This is deliberately separate from writing config.yaml: the URL must only be
// committed AFTER mihomo has accepted the new config, otherwise a failed reload
// leaves the UI advertising a subscription that is not actually loaded.
func (m *Manager) WriteSubscriptionURLAtomic(url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return writeFileAtomic(m.subURLPath(), []byte(url))
}

// RenderSubscription builds the config bytes for a subscription without
// touching disk, so a caller can stage and validate before committing.
func (m *Manager) RenderSubscription(fullYAML []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.renderSubscriptionUnsafe(fullYAML)
}

// TightenExistingPerms fixes up files written by an older build.
//
// The atomic writer creates new files at 0600, but a file that already exists
// keeps whatever mode it was created with — on a live box config.yaml was
// still 0644, world-readable, holding node passwords and the controller
// secret. Existing installs would only get fixed on their next write, which
// may never happen. Called once at startup.
//
// Best-effort: a chmod failure must not stop the service from starting.
func (m *Manager) TightenExistingPerms() {
	dir := filepath.Dir(m.Path)
	for _, p := range []string{
		m.Path,
		m.Path + ".bak",
		m.subURLPath(),
		m.overridesPath(),
		filepath.Join(dir, ".fnos-admin-token"),
	} {
		info, err := os.Lstat(p)
		// Regular files only: never chase a symlink planted at these paths.
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Mode().Perm() != configPerm {
			_ = os.Chmod(p, configPerm)
		}
	}
}
