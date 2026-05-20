package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"

	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
	"github.com/conversun/fnos-mihomo-dashboard/internal/mihomo"
)

type Handlers struct {
	cfg     *config.Manager
	logFile string
	mihomo  *mihomo.Client
	confPath string
}

func New(configFile, logFile string, mihomoAPI *url.URL) *Handlers {
	return &Handlers{
		cfg:      config.New(configFile),
		logFile:  logFile,
		mihomo:   mihomo.New(mihomoAPI),
		confPath: configFile,
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
		if err := h.cfg.SetSubscription(body.URL); err != nil {
			writeErr(w, 500, err)
			return
		}
		// Trigger mihomo to reload from updated config.yaml
		if err := h.mihomo.ReloadConfigPath(h.confPath); err != nil {
			writeJSON(w, 200, map[string]any{
				"ok":      true,
				"warning": "config saved but mihomo reload failed: " + err.Error(),
			})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// GET /api/status → {version: ..., currentProxy: ...}
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	if v, err := h.mihomo.Version(); err == nil {
		out["version"] = v
	} else {
		out["version_error"] = err.Error()
	}
	if p, err := h.mihomo.Proxies(); err == nil {
		// Extract PROXY group's current selection
		if all, ok := p["proxies"].(map[string]any); ok {
			if proxyGroup, ok := all["PROXY"].(map[string]any); ok {
				out["current_proxy"] = proxyGroup["now"]
			}
		}
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

// GET /api/proxies → returns the raw proxies map from mihomo
func (h *Handlers) Proxies(w http.ResponseWriter, r *http.Request) {
	p, err := h.mihomo.Proxies()
	if err != nil {
		writeErr(w, 502, err)
		return
	}
	writeJSON(w, 200, p)
}

// POST /api/proxies/select  body {group: "PROXY", name: "..."}
func (h *Handlers) SelectProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Group string `json:"group"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err)
		return
	}
	if body.Group == "" {
		body.Group = "PROXY"
	}
	if err := h.mihomo.SelectProxy(body.Group, body.Name); err != nil {
		writeErr(w, 502, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
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

type errStr string

func (e errStr) Error() string { return string(e) }

var errEmptyURL = errStr("subscription url cannot be empty")
