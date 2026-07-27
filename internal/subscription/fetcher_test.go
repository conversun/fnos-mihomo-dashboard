package subscription

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// The subscription URL is fetched server-side from an unauthenticated endpoint,
// so it must not become a probe into the NAS's own network.
func TestBlockedIPCoversPrivateRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.5", "172.16.0.1", "192.168.1.1", // RFC1918
		"fd00::1",         // IPv6 ULA
		"169.254.169.254", // cloud metadata
		"100.64.0.1",      // CGNAT
		"0.0.0.0", "::",   // unspecified
		"224.0.0.1", // multicast
		"fe80::1",   // link-local
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "104.16.0.1", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = true, want false (public address)", s)
		}
	}

	if !isBlockedIP(nil) {
		t.Error("a nil IP must be treated as blocked")
	}
}

func TestValidateURLRejectsUnsafeShapes(t *testing.T) {
	bad := []string{
		"file:///etc/passwd",
		"ftp://example.com/sub.yaml",
		"javascript:alert(1)",
		"http://user:pass@example.com/sub.yaml", // embedded credentials
		"http://",
		"not-a-url",
	}
	for _, s := range bad {
		if _, err := validateURL(s); err == nil {
			t.Errorf("validateURL(%q) accepted an unsafe URL", s)
		}
	}
	for _, s := range []string{"http://example.com/sub.yaml", "https://example.com/a?b=c"} {
		if _, err := validateURL(s); err != nil {
			t.Errorf("validateURL(%q) rejected a valid URL: %v", s, err)
		}
	}
}

// A private target must fail, and must fail with the SAME message as any other
// fetch failure — distinct errors let a caller tell open ports from closed ones.
func TestFetchDoesNotLeakPortState(t *testing.T) {
	// An open local port and a closed one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openURL := "http://" + ln.Addr().String() + "/sub.yaml"
	closedURL := "http://127.0.0.1:1/sub.yaml"

	_, _, errOpen := FetchFullYAML(openURL)
	_, _, errClosed := FetchFullYAML(closedURL)

	if errOpen == nil || errClosed == nil {
		t.Fatal("both loopback targets must be refused")
	}
	if !errors.Is(errOpen, ErrFetchFailed) || !errors.Is(errClosed, ErrFetchFailed) {
		t.Errorf("errors must be the uniform ErrFetchFailed; got %v / %v", errOpen, errClosed)
	}
	if errOpen.Error() != errClosed.Error() {
		t.Errorf("error text distinguishes open from closed ports:\n open  : %v\n closed: %v", errOpen, errClosed)
	}
	if strings.Contains(errOpen.Error(), "refused") || strings.Contains(errClosed.Error(), "refused") {
		t.Error("error text leaks the connection outcome")
	}
}

func TestParseUserInfoHeader(t *testing.T) {
	info := parseUserInfoHeader("upload=1; download=2; total=3; expire=4", "https://x/y")
	if info == nil {
		t.Fatal("expected parsed info")
	}
	if info.Upload != 1 || info.Download != 2 || info.Total != 3 || info.Expire != 4 {
		t.Errorf("parsed %+v, want 1/2/3/4", info)
	}
	if parseUserInfoHeader("", "https://x/y") != nil {
		t.Error("absent header must yield nil, not an empty Info")
	}
	// Malformed pairs are skipped, not fatal.
	if got := parseUserInfoHeader("upload=abc; total=5", "u"); got == nil || got.Total != 5 || got.Upload != 0 {
		t.Errorf("malformed pair mishandled: %+v", got)
	}
}
