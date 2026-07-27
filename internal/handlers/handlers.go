package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
	"github.com/conversun/fnos-mihomo-dashboard/internal/mihomo"
	"github.com/conversun/fnos-mihomo-dashboard/internal/subscription"
	"github.com/conversun/fnos-mihomo-dashboard/internal/supervisor"
)

type Handlers struct {
	// applyMu serializes whole subscription transactions (stage -> reload ->
	// commit). config.Manager's own lock only guards individual file ops.
	applyMu sync.Mutex

	cfg      *config.Manager
	logFile  string
	mihomo   *mihomo.Client
	confPath string
	subInfo  *subscription.Cache
	sup      *supervisor.Supervisor
}

func New(configFile, logFile string, mihomoAPI *url.URL, sup *supervisor.Supervisor) *Handlers {
	return &Handlers{
		cfg:      config.New(configFile),
		logFile:  logFile,
		mihomo:   mihomo.New(mihomoAPI),
		confPath: configFile,
		subInfo:  subscription.NewCache(),
		sup:      sup,
	}
}

// maxJSONBody caps request bodies. The override endpoint accepts free-form
// YAML strings, so without a limit a single request could stream unbounded
// data into memory on a root-run service.
const maxJSONBody = 1 << 20 // 1 MiB

// decodeJSON reads a bounded, strict JSON body.
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// GET  /api/subscription  → {url: "..."}
// POST /api/subscription  body {url: "..."} → set + trigger mihomo reload
func (h *Handlers) Subscription(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		u, err := h.cfg.GetSubscription()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		// The subscription URL embeds the airline token — usually the most
		// reusable credential in the system. Report only whether one is set
		// and which host it points at.
		writeJSON(w, 200, map[string]any{
			"configured": u != "",
			"url":        config.MaskSubscriptionURL(u),
		})

	case http.MethodPost:
		var body struct {
			URL string `json:"url"`
		}
		if err := decodeJSON(w, r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		if body.URL == "" {
			writeErr(w, 400, errEmptyURL)
			return
		}
		// One request only: FetchFullYAML already validates status, yaml shape
		// and the proxies list. A separate pre-flight Validate() meant two GETs
		// with a TOCTOU window between them. We preserve the user's proxies /
		// proxy-groups / rules / rule-providers and only override fnOS-managed
		// fields (external-controller, profile, dns, tun, sniffer).
		fullYAML, info, err := subscription.FetchFullYAML(body.URL)
		if err != nil {
			writeErr(w, 400, fmt.Errorf("fetch subscription: %w", err))
			return
		}
		if err := h.applySubscription(body.URL, fullYAML); err != nil {
			writeApplyError(w, err)
			return
		}
		if info != nil {
			h.subInfo.Put(body.URL, info)
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// GET /api/status → health state + version
//
// Health is a state, not a boolean. A live child process proves nothing about
// whether the API we drive belongs to it: a mihomo that lost the race for the
// controller port stays alive while another process answers on that port, and
// the old code reported that as healthy (see supervisor.OwnsListener).
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	out := map[string]any{}

	processAlive := false
	pid := 0
	if h.sup != nil {
		processAlive = h.sup.Running()
		pid = h.sup.PID()
	}

	version, verr := h.mihomo.Version()
	apiReachable := verr == nil
	if apiReachable {
		out["version"] = version
	} else {
		out["version_error"] = verr.Error()
	}

	apiOwned := false
	if processAlive && apiReachable && h.mihomo.BaseURL != nil {
		if owned, err := supervisor.OwnsListener(pid, h.mihomo.BaseURL.Host); err == nil {
			apiOwned = owned
		}
	}

	state := "stopped"
	switch {
	case processAlive && apiReachable && apiOwned:
		state = "healthy"
	case processAlive && apiReachable && !apiOwned:
		// Someone else answers on the controller port. Driving it would
		// reconfigure a process we do not supervise.
		state = "foreign_api"
	case processAlive && !apiReachable:
		state = "api_unreachable"
	}

	out["mihomo_state"] = state
	out["process_alive"] = processAlive
	out["api_reachable"] = apiReachable
	out["api_owned"] = apiOwned
	out["mihomo_pid"] = pid
	// Kept for UI compatibility, but now means "actually usable", not merely
	// "a process exists".
	out["mihomo_running"] = state == "healthy"

	writeJSON(w, 200, out)
}

// GET /api/logs → last ~100 lines of mihomo.log
func (h *Handlers) Logs(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(h.logFile)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	// Return last 100 lines
	lines := splitLastN(b, 100)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(lines)
}

// POST /api/reload — force mihomo to reload config.yaml from disk
func (h *Handlers) Reload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := h.mihomo.ReloadConfigPath(h.confPath); err != nil {
		writeErr(w, 502, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/subscription/info — returns cached subscription-userinfo (used / total / expire)
func (h *Handlers) SubscriptionInfo(w http.ResponseWriter, r *http.Request) {
	url, err := h.cfg.GetSubscription()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if url == "" {
		writeJSON(w, 200, map[string]any{"present": false})
		return
	}
	info := h.subInfo.Get(url)
	if info == nil {
		// fetch on-demand
		if fetched, ferr := subscription.Fetch(url); ferr == nil {
			h.subInfo.Put(url, fetched)
			info = fetched
		}
	}
	if info == nil {
		writeJSON(w, 200, map[string]any{"present": true, "info": nil, "url": config.MaskSubscriptionURL(url)})
		return
	}
	writeJSON(w, 200, map[string]any{"present": true, "info": info})
}

// POST /api/subscription/refresh — dashboard re-pulls the subscription URL,
// re-extracts proxies, rewrites the local provider file, then asks mihomo to
// reload that provider.
func (h *Handlers) SubscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	url, err := h.cfg.GetSubscription()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if url == "" {
		writeErr(w, 400, fmt.Errorf("no subscription URL configured yet"))
		return
	}
	fullYAML, info, err := subscription.FetchFullYAML(url)
	if err != nil {
		writeErr(w, 502, err)
		return
	}
	// Same transaction as a manual save. Previously this discarded the reload
	// error and always returned ok:true, so a scheduled refresh could write a
	// config mihomo never loaded and report success — silently breaking the
	// user's gateway with no signal anywhere.
	if err := h.applySubscription(url, fullYAML); err != nil {
		writeApplyError(w, err)
		return
	}
	if info != nil {
		h.subInfo.Put(url, info)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/config — return raw config.yaml content (post-override)
func (h *Handlers) Config(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Credential values are masked. A subscription populates this file with
	// per-node passwords/UUIDs, so serving it verbatim handed every reader the
	// user's paid airline account.
	b, err := h.cfg.RedactedYAML()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b)
}

// GET  /api/overrides — list fnOS overrides and current editable settings
// POST /api/overrides — save override switches and YAML snippets
// DELETE /api/overrides — reset to built-in defaults
func (h *Handlers) Overrides(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := h.cfg.OverrideSettings()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"settings":  settings,
			"defaults":  config.DefaultOverrideSettings(),
			"overrides": h.cfg.AppliedOverrides(),
		})
	case http.MethodPost:
		var settings config.OverrideSettings
		if err := decodeJSON(w, r, &settings); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := h.cfg.SetOverrideSettings(settings); err != nil {
			writeErr(w, 400, err)
			return
		}
		saved, _ := h.cfg.OverrideSettings()
		writeJSON(w, 200, map[string]any{
			"ok":        true,
			"settings":  saved,
			"defaults":  config.DefaultOverrideSettings(),
			"overrides": h.cfg.AppliedOverrides(),
		})
	case http.MethodDelete:
		if err := h.cfg.ResetOverrideSettings(); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":        true,
			"settings":  config.DefaultOverrideSettings(),
			"defaults":  config.DefaultOverrideSettings(),
			"overrides": h.cfg.AppliedOverrides(),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// POST /api/mihomo/start — start the supervised mihomo process
func (h *Handlers) MihomoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.sup == nil {
		writeErr(w, 503, fmt.Errorf("supervisor not configured"))
		return
	}
	if err := h.sup.Start(); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pid": h.sup.PID()})
}

// POST /api/mihomo/stop — stop the supervised mihomo process
func (h *Handlers) MihomoStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.sup == nil {
		writeErr(w, 503, fmt.Errorf("supervisor not configured"))
		return
	}
	if err := h.sup.Stop(); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/mihomo/restart — stop then start
func (h *Handlers) MihomoRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.sup == nil {
		writeErr(w, 503, fmt.Errorf("supervisor not configured"))
		return
	}
	if err := h.sup.Restart(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pid": h.sup.PID()})
}

// splitLastN returns the last n lines of b (joined with newline).
func splitLastN(b []byte, n int) []byte {
	count := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			count++
			if count >= n {
				return b[i+1:]
			}
		}
	}
	return b
}

func rollbackErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type errStr string

func (e errStr) Error() string { return string(e) }

var errEmptyURL = errStr("subscription url cannot be empty")
