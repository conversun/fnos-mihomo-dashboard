package subscription

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Info captures the airline-style subscription metadata returned via the
// `subscription-userinfo` HTTP response header by Clash subscription endpoints.
//
//	subscription-userinfo: upload=44137197; download=24471430; total=10737418240; expire=1671235200
type Info struct {
	Upload    int64 `json:"upload"`
	Download  int64 `json:"download"`
	Total     int64 `json:"total"`
	Expire    int64 `json:"expire"`     // unix seconds; 0 if absent
	UpdatedAt int64 `json:"updated_at"` // unix seconds when this Info was fetched
	// URL is intentionally NOT serialized: it carries the subscription token.
	URL string `json:"-"`
}

// parseUserInfoHeader parses the airline-style `subscription-userinfo` header:
//
//	upload=44137197; download=24471430; total=10737418240; expire=1671235200
//
// Returns nil when the header is absent, so callers can treat metadata as
// best-effort.
func parseUserInfoHeader(header, rawURL string) *Info {
	if header == "" {
		return nil
	}
	info := &Info{UpdatedAt: time.Now().Unix(), URL: rawURL}
	for _, kv := range strings.Split(header, ";") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) != 2 {
			continue
		}
		val, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(parts[0]) {
		case "upload":
			info.Upload = val
		case "download":
			info.Download = val
		case "total":
			info.Total = val
		case "expire":
			info.Expire = val
		}
	}
	return info
}

var ErrNoUserInfo = errors.New("subscription URL did not return subscription-userinfo header")

// Cache holds the most recent Info per URL.
type Cache struct {
	mu    sync.RWMutex
	items map[string]*Info
}

func NewCache() *Cache {
	return &Cache{items: map[string]*Info{}}
}

func (c *Cache) Get(url string) *Info {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.items[url]
}

func (c *Cache) Put(url string, info *Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[url] = info
}

// Fetch performs a GET with a Clash-style User-Agent (most airlines key on it)
// and parses the subscription-userinfo header without downloading the full body.
func Fetch(rawURL string) (*Info, error) {
	u, err := validateURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrFetchFailed
	}
	req.Header.Set("User-Agent", "clash.meta")
	resp, err := newClient(30 * time.Second).Do(req)
	if err != nil {
		log.Printf("subscription: fetch %s failed: %v", u.Host, err)
		return nil, fetchError(err)
	}
	defer resp.Body.Close()
	info := parseUserInfoHeader(resp.Header.Get("subscription-userinfo"), rawURL)
	if info == nil {
		return nil, ErrNoUserInfo
	}
	return info, nil
}

// FetchFullYAML downloads the subscription URL and returns the full raw yaml
// body (so callers can use it as the entire mihomo config) along with
// subscription-userinfo. Validates that the body parses as yaml and contains
// a non-empty proxies list — refuses to save junk.
func FetchFullYAML(rawURL string) (body []byte, info *Info, err error) {
	u, err := validateURL(rawURL)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, ErrFetchFailed
	}
	req.Header.Set("User-Agent", "clash.meta")
	resp, err := newClient(60 * time.Second).Do(req)
	if err != nil {
		log.Printf("subscription: fetch %s failed: %v", u.Host, err)
		return nil, nil, fetchError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Deliberately does NOT echo the status: distinct codes let a caller
		// probe internal ports.
		log.Printf("subscription: fetch %s returned HTTP %d", u.Host, resp.StatusCode)
		return nil, nil, ErrFetchFailed
	}
	// Read one extra byte so an oversized body is rejected rather than
	// silently truncated into invalid yaml.
	const maxBody = 16 << 20
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, nil, ErrFetchFailed
	}
	if len(body) > maxBody {
		return nil, nil, fmt.Errorf("%w: subscription is larger than 16 MiB", ErrFetchFailed)
	}
	var probe map[string]any
	if err := yaml.Unmarshal(body, &probe); err != nil {
		return nil, nil, fmt.Errorf("parse subscription yaml: %w", err)
	}
	if proxies, _ := probe["proxies"].([]any); len(proxies) == 0 {
		return nil, nil, errors.New("subscription yaml has no `proxies` field (empty / not a Clash subscription?)")
	}
	return body, parseUserInfoHeader(resp.Header.Get("subscription-userinfo"), rawURL), nil
}
