package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ApplyError describes a failed subscription apply, including whether the
// rollback itself succeeded. Callers surface rollback failure prominently:
// it is the difference between "nothing changed" and "the gateway may be down".
type ApplyError struct {
	Cause          error
	RollbackWrite  error
	RollbackReload error
}

func (e *ApplyError) Error() string {
	var b strings.Builder
	b.WriteString(e.Cause.Error())
	if e.RollbackWrite != nil {
		b.WriteString("; rollback write failed: " + e.RollbackWrite.Error())
	}
	if e.RollbackReload != nil {
		b.WriteString("; rollback reload failed: " + e.RollbackReload.Error())
	}
	return b.String()
}

func (e *ApplyError) Unwrap() error { return e.Cause }

// RolledBack reports whether the previous config was fully restored.
func (e *ApplyError) RolledBack() bool {
	return e.RollbackWrite == nil && e.RollbackReload == nil
}

// applySubscription commits a subscription as one transaction.
//
// The transaction boundary is: candidate config on disk AND accepted by the
// supervised mihomo AND the matching subscription URL committed. Anything less
// is rolled back to the exact bytes that were live beforehand.
//
// Two properties matter, both learned from observed failures:
//
//   - The URL sidecar is written only AFTER a successful reload. Writing it
//     first (the previous behavior) meant a failed reload restored config.yaml
//     but left the URL set, so the UI advertised a subscription that mihomo had
//     never loaded.
//   - The pre-state is an in-memory snapshot, not the shared config.yaml.bak.
//     A single shared backup file can be overwritten by a concurrent save, so
//     restoring from it could install another request's config.
//
// applyMu serializes the whole sequence so two applies cannot interleave their
// stage/reload/commit steps.
func (h *Handlers) applySubscription(rawURL string, fullYAML []byte) error {
	h.applyMu.Lock()
	defer h.applyMu.Unlock()

	// Snapshot BEFORE any mutation. A failure here is fatal: without a known
	// pre-state there is no safe way to roll back.
	before, err := h.cfg.ReadRaw()
	if err != nil {
		return fmt.Errorf("snapshot current config: %w", err)
	}

	candidate, err := h.cfg.RenderSubscription(fullYAML)
	if err != nil {
		return err
	}

	if err := h.cfg.WriteRawAtomic(candidate); err != nil {
		return fmt.Errorf("stage subscription config: %w", err)
	}

	if err := h.mihomo.ReloadConfigPath(h.confPath); err != nil {
		return h.rollbackConfig(before, fmt.Errorf("mihomo reload failed: %w", err))
	}

	// mihomo accepted the candidate — only now is the URL true.
	if err := h.cfg.WriteSubscriptionURLAtomic(rawURL); err != nil {
		return h.rollbackConfig(before, fmt.Errorf("commit subscription url: %w", err))
	}

	return nil
}

// rollbackConfig restores the snapshot and reloads mihomo from it, reporting
// both the original cause and any rollback failure.
func (h *Handlers) rollbackConfig(before []byte, cause error) error {
	writeErr := h.cfg.WriteRawAtomic(before)
	var reloadErr error
	if writeErr == nil {
		reloadErr = h.mihomo.ReloadConfigPath(h.confPath)
	}
	return &ApplyError{Cause: cause, RollbackWrite: writeErr, RollbackReload: reloadErr}
}

// writeApplyError turns an apply failure into an HTTP response that tells the
// user whether their gateway is still in a good state.
func writeApplyError(w http.ResponseWriter, err error) {
	var ae *ApplyError
	if errors.As(err, &ae) {
		status := http.StatusBadGateway
		payload := map[string]any{
			"error":       "mihomo reload failed; config rolled back",
			"detail":      ae.Cause.Error(),
			"rolled_back": ae.RolledBack(),
		}
		if !ae.RolledBack() {
			// The dangerous case: we could not restore the previous config, so
			// the gateway may be down. Say so loudly rather than implying the
			// system is untouched.
			status = http.StatusInternalServerError
			payload["error"] = "mihomo reload failed AND rollback failed; the proxy may be misconfigured"
			payload["rollback_error"] = rollbackErr(errors.Join(ae.RollbackWrite, ae.RollbackReload))
		}
		writeJSON(w, status, payload)
		return
	}
	writeErr(w, http.StatusInternalServerError, err)
}
