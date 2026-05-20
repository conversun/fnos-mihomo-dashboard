package mihomo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	BaseURL *url.URL
	HTTP    *http.Client
}

func New(baseURL *url.URL) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	u := *c.BaseURL
	u.Path = path
	var br io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		br = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u.String(), br)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.HTTP.Do(req)
}

// Version returns mihomo version info.
func (c *Client) Version() (map[string]any, error) {
	resp, err := c.do(http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("mihomo /version returned %d", resp.StatusCode)
	}
	var out map[string]any
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// Proxies returns all proxies and groups.
func (c *Client) Proxies() (map[string]any, error) {
	resp, err := c.do(http.MethodGet, "/proxies", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("mihomo /proxies returned %d", resp.StatusCode)
	}
	var out map[string]any
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// SelectProxy sets a proxy in a select group.
func (c *Client) SelectProxy(group, name string) error {
	resp, err := c.do(http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": name})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mihomo /proxies/%s returned %d: %s", group, resp.StatusCode, b)
	}
	return nil
}

// ReloadConfigPath asks mihomo to reload config from a local file path.
// This DOES NOT change external-controller (mihomo reads from file, which fnos-dashboard controls).
func (c *Client) ReloadConfigPath(path string) error {
	u := *c.BaseURL
	u.Path = "/configs"
	u.RawQuery = "force=true"
	body, _ := json.Marshal(map[string]string{"path": path})
	req, _ := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mihomo /configs reload returned %d: %s", resp.StatusCode, b)
	}
	return nil
}
