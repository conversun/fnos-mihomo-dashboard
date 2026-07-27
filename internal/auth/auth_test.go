package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached"))
	})
}

// The reverse proxy at /mihomo/* exposes mihomo's full write-capable
// controller. Verified on a live box that an unauthenticated PATCH from
// another host changed the running proxy mode, so a LAN caller must be
// rejected before reaching it.
func TestProtectRejectsUnauthenticatedRemote(t *testing.T) {
	g := New("s3cret", true)
	srv := httptest.NewServer(g.Protect(okHandler()))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodPatch, "/mihomo/configs", nil)
	req.RemoteAddr = "192.168.1.50:40000" // a LAN peer, not the NAS itself
	rec := httptest.NewRecorder()
	g.Protect(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an unauthenticated LAN caller", rec.Code)
	}
	if rec.Body.String() == "reached" {
		t.Error("request reached the protected handler")
	}
}

func TestProtectAcceptsValidToken(t *testing.T) {
	g := New("s3cret", false)
	for _, tc := range []struct {
		name string
		set  func(*http.Request)
	}{
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret") }},
		{"x-token", func(r *http.Request) { r.Header.Set("X-Token", "s3cret") }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "token=s3cret" }},
		{"cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "fnos_admin_token", Value: "s3cret"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			req.RemoteAddr = "192.168.1.50:40000"
			tc.set(req)
			rec := httptest.NewRecorder()
			g.Protect(okHandler()).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 with a valid token", rec.Code)
			}
		})
	}
}

func TestProtectRejectsWrongToken(t *testing.T) {
	g := New("s3cret", false)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "192.168.1.50:40000"
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	g.Protect(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// An empty token must never degrade into "allow everyone".
func TestEmptyTokenFailsClosedForRemote(t *testing.T) {
	g := New("", false)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "192.168.1.50:40000"
	rec := httptest.NewRecorder()
	g.Protect(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no token is configured", rec.Code)
	}
}

// Loopback stays open so the bundled UI, local curl and the auto-refresh
// ticker keep working without configuration.
func TestLoopbackExempt(t *testing.T) {
	g := New("s3cret", true)
	for _, addr := range []string{"127.0.0.1:5000", "[::1]:5000"} {
		req := httptest.NewRequest(http.MethodPost, "/api/subscription/refresh", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		g.Protect(okHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("loopback %s got %d, want 200", addr, rec.Code)
		}
	}
}

func TestLoadOrCreateTokenPersistsAt0600(t *testing.T) {
	dir := t.TempDir()
	tok, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 32 {
		t.Errorf("token too short: %d chars", len(tok))
	}
	info, err := os.Stat(filepath.Join(dir, TokenFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %v, want 0600 (credential material)", perm)
	}
	// Second call must return the same token, not rotate it.
	again, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again != tok {
		t.Error("token rotated on reload; existing clients would break")
	}
}
