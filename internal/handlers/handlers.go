package handlers

import (
	"fmt"
	"encoding/json"
	"net/http"
	"net/url"
	"os"

	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
	"github.com/conversun/fnos-mihomo-dashboard/internal/mihomo"
	"github.com/conversun/fnos-mihomo-dashboard/internal/subscription"
	"github.com/conversun/fnos-mihomo-dashboard/internal/supervisor"
)

type Handlers struct {
	cfg     *config.Manager
	logFile string
	mihomo  *mihomo.Client
	confPath string
	subInfo *subscription.Cache
	sup     *supervisor.Supervisor
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
		writeJSON(w, 200, map[string]string{"url": u})

	case http.MethodPost:
		var body struct{ URL string `json:"url"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		if body.URL == "" {
			writeErr(w, 400, errEmptyURL)
			return
		}
		if err := subscription.Validate(body.URL); err != nil {
			writeErr(w, 400, err)
			return
		}
		// Pull full subscription yaml. We preserve the user's proxies /
		// proxy-groups / rules / rule-providers and only override fnOS-managed
		// fields (external-controller, profile, dns, tun, sniffer).
		fullYAML, info, err := subscription.FetchFullYAML(body.URL)
		if err != nil {
			writeErr(w, 400, fmt.Errorf("fetch subscription: %w", err))
			return
		}
		bakPath, _ := h.cfg.Backup()
		if err := h.cfg.SetSubscriptionFromURL(body.URL, fullYAML); err != nil {
			writeErr(w, 500, err)
			return
		}
		if err := h.mihomo.ReloadConfigPath(h.confPath); err != nil {
			rbErr := h.cfg.RestoreFromBackup()
			_ = h.mihomo.ReloadConfigPath(h.confPath)
			writeJSON(w, 502, map[string]any{
				"error":          "mihomo reload failed; config rolled back",
				"detail":         err.Error(),
				"rollback_error": rollbackErr(rbErr),
				"backup":         bakPath,
			})
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

// GET /api/status → {version: ..., currentProxy: ...}
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	if h.sup != nil {
		out["mihomo_running"] = h.sup.Running()
		out["mihomo_pid"] = h.sup.PID()
	}
	if v, err := h.mihomo.Version(); err == nil {
		out["version"] = v
	} else {
		out["version_error"] = err.Error()
	}
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
		writeJSON(w, 200, map[string]any{"present": true, "info": nil, "url": url})
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
	if err := h.cfg.SetSubscriptionFromURL(url, fullYAML); err != nil {
		writeErr(w, 500, err)
		return
	}
	// Trigger a full mihomo reload from disk so all changed fields take effect
	_ = h.mihomo.ReloadConfigPath(h.confPath)
	if info != nil {
		h.subInfo.Put(url, info)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/config — return raw config.yaml content (post-override)
func (h *Handlers) Config(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(h.confPath)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b)
}

// GET /api/overrides — list fnOS overrides applied to every saved config
func (h *Handlers) Overrides(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"overrides": h.cfg.AppliedOverrides(),
	})
}

// POST /api/mihomo/start — start the supervised mihomo process
func (h *Handlers) MihomoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	if h.sup == nil { writeErr(w, 503, fmt.Errorf("supervisor not configured")); return }
	if err := h.sup.Start(); err != nil { writeErr(w, 409, err); return }
	writeJSON(w, 200, map[string]any{"ok": true, "pid": h.sup.PID()})
}

// POST /api/mihomo/stop — stop the supervised mihomo process
func (h *Handlers) MihomoStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	if h.sup == nil { writeErr(w, 503, fmt.Errorf("supervisor not configured")); return }
	if err := h.sup.Stop(); err != nil { writeErr(w, 409, err); return }
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/mihomo/restart — stop then start
func (h *Handlers) MihomoRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	if h.sup == nil { writeErr(w, 503, fmt.Errorf("supervisor not configured")); return }
	if err := h.sup.Restart(); err != nil { writeErr(w, 500, err); return }
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
