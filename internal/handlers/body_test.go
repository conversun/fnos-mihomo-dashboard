package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
)

// The service is root-run and the loopback path is unauthenticated, so an
// unbounded JSON body is a free memory-exhaustion primitive — the override
// endpoint in particular accepts free-form YAML strings.
func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	var out struct {
		URL string `json:"url"`
	}
	huge := `{"url":"` + strings.Repeat("A", maxJSONBody+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/subscription", strings.NewReader(huge))
	rec := httptest.NewRecorder()

	if err := decodeJSON(rec, req, &out); err == nil {
		t.Fatal("oversized body was accepted; expected it to be rejected")
	}
}

func TestDecodeJSONAcceptsNormalBody(t *testing.T) {
	var out struct {
		URL string `json:"url"`
	}
	req := httptest.NewRequest(http.MethodPost, "/api/subscription",
		strings.NewReader(`{"url":"https://example.com/sub.yaml"}`))
	rec := httptest.NewRecorder()

	if err := decodeJSON(rec, req, &out); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	if out.URL != "https://example.com/sub.yaml" {
		t.Errorf("URL = %q, want the posted URL", out.URL)
	}
}

// decodeJSON uses DisallowUnknownFields, so the settings object the UI receives
// from GET /api/overrides must decode cleanly when POSTed straight back. The
// frontend does exactly that: applyOverridePayload stores d.settings and
// saveOverrides sends it verbatim.
func TestOverrideSettingsRoundTripsThroughStrictDecoder(t *testing.T) {
	// Exactly what the GET handler serializes.
	payload, err := json.Marshal(config.DefaultOverrideSettings())
	if err != nil {
		t.Fatal(err)
	}

	var out config.OverrideSettings
	req := httptest.NewRequest(http.MethodPost, "/api/overrides", strings.NewReader(string(payload)))
	rec := httptest.NewRecorder()

	if err := decodeJSON(rec, req, &out); err != nil {
		t.Fatalf("settings from GET failed to decode on POST: %v", err)
	}
	if out.ProfileYAML == "" || out.DNSYAML == "" || out.TUNYAML == "" || out.SnifferYAML == "" {
		t.Error("round trip lost the editable YAML snippets")
	}
}
