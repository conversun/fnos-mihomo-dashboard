package subscription

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrBlockedTarget is returned when a subscription URL resolves to an address
// the fetcher refuses to contact.
//
// This is deliberately NOT folded into ErrFetchFailed. Telling a user their LAN
// URL is "unreachable" is false and sends them debugging their own web server;
// self-hosting the Clash config on the NAS is a natural thing to try. Naming the
// category leaks nothing they did not already supply -- the caller chose the
// address, and the resolved IP is never echoed back (see fetchError).
var ErrBlockedTarget = errors.New("subscription URL resolves to a private or local " +
	"address, which the dashboard refuses to fetch; use a publicly reachable URL")

// ErrFetchFailed is the single, uniform error surfaced to callers for any
// network-level failure.
//
// The dashboard has no authentication for the UI's own fetch, and a
// user-supplied URL is fetched server-side. Distinct error strings turned that
// into a port scanner: "connection refused" (closed) vs "returned HTTP 400"
// (open) vs "no proxies field" (open, serving YAML-ish) let a caller map the
// NAS's internal network. Everything now collapses to one message; details go
// to the server log only.
var ErrFetchFailed = errors.New("subscription fetch failed: check the URL is a reachable Clash subscription")

// fetchError maps a transport failure onto the error the caller may see.
//
// Two rules, both load-bearing:
//   - A blocked target returns the BARE sentinel. safeTransport wraps it with the
//     concrete IP for the server log; returning that wrapped value would confirm
//     internal DNS mappings to whoever supplied the URL.
//   - Everything else collapses to ErrFetchFailed, so an open port and a closed
//     one remain indistinguishable.
func fetchError(err error) error {
	if errors.Is(err, ErrBlockedTarget) {
		return ErrBlockedTarget
	}
	return ErrFetchFailed
}

// safeTransport blocks private/loopback destinations at DIAL time.
//
// Validating the hostname before dialing is not enough: DNS rebinding can
// return a public address on first resolution and a private one when the
// connection is actually made. Checking inside DialContext sees the address
// the kernel will really connect to.
func safeTransport() *http.Transport {
	return &http.Transport{
		// Never honor HTTP_PROXY: a proxy would make the dial target the proxy
		// itself, silently bypassing every address check below.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					lastErr = fmt.Errorf("%w: %s", ErrBlockedTarget, ip.IP)
					continue
				}
				d := net.Dialer{Timeout: 10 * time.Second}
				conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = ErrBlockedTarget
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// isBlockedIP reports whether an address is off-limits for server-side fetches.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip.IsPrivate() { // RFC1918 + IPv6 ULA
		return true
	}
	// Carrier-grade NAT and the cloud metadata range.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1]&0xC0 == 64 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}

// validateURL enforces scheme and shape before any network activity.
func validateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, ErrFetchFailed
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("%w: only http(s) subscription URLs are supported", ErrFetchFailed)
	}
	if u.Host == "" {
		return nil, ErrFetchFailed
	}
	// Credentials in the URL would be forwarded on redirects.
	if u.User != nil {
		return nil, fmt.Errorf("%w: URL must not embed credentials", ErrFetchFailed)
	}
	return u, nil
}

// newClient builds the hardened client used for every subscription fetch.
func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: safeTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("%w: too many redirects", ErrFetchFailed)
			}
			// Re-validate every hop; a public URL can redirect to 127.0.0.1.
			if _, err := validateURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}
