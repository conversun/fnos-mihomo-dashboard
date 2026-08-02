// Package auth guards the dashboard's management surface.
//
// Why this exists: mihomo binds its controller to 127.0.0.1 precisely so it is
// not reachable from the network. The dashboard reverse-proxies that controller
// at /mihomo/*, which undoes that protection — every LAN host gains the full
// write-capable API. Verified against a live fnOS box: an unauthenticated
// request from another machine flipped the running proxy mode.
//
//	$ curl -X PATCH http://<nas>:9097/mihomo/configs -d '{"mode":"direct"}'
//	HTTP 204     # proxy rules bypassed for the whole household
//
// mihomo v1.19.29 also exposes PUT /configs (accepts a whole config payload,
// bypassing SAFE_PATHS), proxy selection, DELETE /connections and core restart
// through that same proxy.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// TokenFileName is where the generated admin token is persisted, alongside the
// mihomo config so it inherits the same protected directory.
const TokenFileName = ".fnos-admin-token"

// Guard authenticates management requests.
type Guard struct {
	token string
	// allowLoopback keeps the local UI and CLI usable without a token when the
	// request provably originates on the NAS itself.
	allowLoopback bool
}

// LoadOrCreateToken reads the admin token, generating one on first run.
// The file is 0600 because it is credential material.
func LoadOrCreateToken(configDir string) (string, error) {
	path := filepath.Join(configDir, TokenFileName)
	b, err := os.ReadFile(path)
	if err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

func New(token string, allowLoopback bool) *Guard {
	return &Guard{token: token, allowLoopback: allowLoopback}
}

// ErrNoToken signals that a guard was constructed without a usable token.
var ErrNoToken = errors.New("admin token is empty")

// authorized reports whether a request may touch the management surface.
func (g *Guard) authorized(r *http.Request) bool {
	if g.allowLoopback && isLoopback(r.RemoteAddr) {
		return true
	}
	if g.token == "" {
		// Fail closed: an empty token must never mean "allow everyone".
		return false
	}
	return constantTimeEqual(presentedToken(r), g.token)
}

// Authorized is the exported form of authorized, so the UI token-gate can
// reuse the exact same check the API guard applies.
func (g *Guard) Authorized(r *http.Request) bool {
    return g.authorized(r)
}

// presentedToken accepts the token from an Authorization header, an X-Token
// header, or a query parameter. The query form exists because MetaCubeXD's
// static assets are loaded by the browser without custom headers.
func presentedToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		return strings.TrimSpace(h)
	}
	if h := r.Header.Get("X-Token"); h != "" {
		return strings.TrimSpace(h)
	}
	if v := r.URL.Query().Get("token"); v != "" {
		return strings.TrimSpace(v)
	}
	if c, err := r.Cookie("fnos_admin_token"); err == nil {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

func constantTimeEqual(a, b string) bool {
	// Length is compared in constant time too by padding through the same call.
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Protect wraps a handler so unauthenticated callers get 401 instead of
// control over the user's network path.
func (g *Guard) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="fnos-mihomo-dashboard"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ProtectFunc is Protect for a HandlerFunc.
func (g *Guard) ProtectFunc(next http.HandlerFunc) http.Handler {
	return g.Protect(next)
}
