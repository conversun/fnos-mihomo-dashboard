package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
	"github.com/conversun/fnos-mihomo-dashboard/internal/mihomo"
	"gopkg.in/yaml.v3"
)

const validSubYAML = `proxies:
  - {name: n1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: PW1}
proxy-groups:
  - {name: PROXY, type: select, proxies: [n1, DIRECT]}
rules:
  - MATCH,PROXY
`

const existingConfig = `mixed-port: 7890
proxies: []
proxy-groups:
  - {name: PROXY, type: select, proxies: [DIRECT]}
rules:
  - MATCH,PROXY
`

// fakeMihomo stands in for the mihomo controller. reloadErr drives the
// failure path that the transaction has to survive.
type fakeMihomo struct {
	mu          sync.Mutex
	reloadFail  bool
	reloadCalls int
	// onReload observes state at the moment mihomo is asked to load the config.
	onReload func()
}

func (f *fakeMihomo) server(t *testing.T) *mihomo.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/configs") {
			f.mu.Lock()
			f.reloadCalls++
			fail := f.reloadFail
			cb := f.onReload
			f.mu.Unlock()
			if cb != nil {
				cb()
			}
			if fail {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"simulated reload failure"}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"meta":true,"version":"v1.19.29"}`))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return mihomo.New(u)
}

func newTestHandlers(t *testing.T, fm *fakeMihomo) (*Handlers, string, string) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(confPath, []byte(existingConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{
		cfg:      config.New(confPath),
		confPath: confPath,
		mihomo:   fm.server(t),
	}
	return h, confPath, filepath.Join(dir, ".fnos-subscription.url")
}

func readOr(t *testing.T, path, fallback string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return fallback
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Test 1 — a failed reload must leave BOTH files byte-identical.
//
// Regression: the old code wrote the URL sidecar first and rolled back only
// config.yaml, so a failed reload left the UI advertising a subscription that
// mihomo had never loaded.
func TestApplySubscriptionRollsBackCompletely(t *testing.T) {
	fm := &fakeMihomo{reloadFail: true}
	h, confPath, urlPath := newTestHandlers(t, fm)

	err := h.applySubscription("https://example.com/sub.yaml", []byte(validSubYAML))
	if err == nil {
		t.Fatal("expected an error when mihomo rejects the config, got nil")
	}

	if got := readOr(t, confPath, ""); got != existingConfig {
		t.Errorf("config.yaml was modified despite rollback:\n%s", got)
	}
	if got := readOr(t, urlPath, "<absent>"); got != "<absent>" {
		t.Errorf("subscription URL was committed despite failed reload: %q", got)
	}
}

// Test 2 — on success the URL is committed only AFTER mihomo accepts.
func TestApplySubscriptionCommitsURLAfterReload(t *testing.T) {
	fm := &fakeMihomo{}
	h, confPath, urlPath := newTestHandlers(t, fm)

	// At reload time the URL must NOT be committed yet.
	fm.onReload = func() {
		if _, err := os.Stat(urlPath); err == nil {
			t.Error("subscription URL was committed BEFORE mihomo accepted the config")
		}
	}

	if err := h.applySubscription("https://example.com/sub.yaml", []byte(validSubYAML)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := readOr(t, confPath, ""); got == existingConfig {
		t.Error("config.yaml was not updated on success")
	}
	if got := readOr(t, urlPath, ""); got != "https://example.com/sub.yaml" {
		t.Errorf("subscription URL = %q, want the new URL", got)
	}
}

// Test 3 — the scheduled refresh path uses the same transaction.
//
// Regression: SubscriptionRefresh discarded the reload error and always
// returned {"ok":true}, so a 12-hourly auto-refresh could write a config that
// mihomo never loaded and report success — silently breaking the gateway.
func TestSubscriptionRefreshReportsReloadFailure(t *testing.T) {
	fm := &fakeMihomo{reloadFail: true}
	h, confPath, urlPath := newTestHandlers(t, fm)

	// Pre-existing subscription, as a scheduled refresh would find.
	if err := os.WriteFile(urlPath, []byte("https://example.com/sub.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validSubYAML))
	}))
	defer sub.Close()
	if err := os.WriteFile(urlPath, []byte(sub.URL), 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/subscription/refresh", nil)
	rec := httptest.NewRecorder()
	h.SubscriptionRefresh(rec, req)

	if rec.Code >= 200 && rec.Code < 300 {
		t.Errorf("refresh returned %d on reload failure; must not report success", rec.Code)
	}
	if got := readOr(t, confPath, ""); got != existingConfig {
		t.Error("refresh left a config mihomo never loaded")
	}
}

// Test 4 — concurrent applies are serialized; no interleaved half-state.
func TestApplySubscriptionSerializes(t *testing.T) {
	fm := &fakeMihomo{}
	h, confPath, _ := newTestHandlers(t, fm)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.applySubscription("https://example.com/sub.yaml", []byte(validSubYAML))
		}()
	}
	wg.Wait()

	// The result must be one coherent config, not a mix.
	var parsed map[string]any
	b, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := yamlUnmarshal(b, &parsed); err != nil {
		t.Fatalf("config.yaml is corrupt after concurrent applies: %v", err)
	}
	if _, ok := parsed["proxies"]; !ok {
		t.Error("config.yaml lost its proxies after concurrent applies")
	}
	// No temp files may survive.
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(confPath), "*.tmp-*"))
	if len(matches) != 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

// Test 5 — apply failure that also fails rollback is reported distinctly.
func TestApplyErrorSignalsRollbackState(t *testing.T) {
	ae := &ApplyError{Cause: errSimulated}
	if !ae.RolledBack() {
		t.Error("clean rollback should report RolledBack() == true")
	}
	ae2 := &ApplyError{Cause: errSimulated, RollbackWrite: errSimulated}
	if ae2.RolledBack() {
		t.Error("failed rollback must report RolledBack() == false")
	}

	rec := httptest.NewRecorder()
	writeApplyError(rec, ae2)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when rollback failed", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["rolled_back"] != false {
		t.Error("response must tell the user the config was NOT restored")
	}
}

var errSimulated = errors.New("simulated")

func yamlUnmarshal(b []byte, out any) error { return yaml.Unmarshal(b, out) }
