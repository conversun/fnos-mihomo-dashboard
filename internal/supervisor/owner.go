package supervisor

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OwnsListener reports whether the supervised process owns the socket
// listening on addr (host:port).
//
// This exists because process liveness alone is a misleading health signal.
// Observed on a live box: a second mihomo lost the race for the controller
// port ("bind: address already in use") yet stayed alive, so the dashboard
// reported mihomo_running=true AND fetched a version — from the OTHER mihomo
// that owned the port. Every subsequent reload would have hit the wrong
// process.
//
// Resolution is done through /proc so it needs no privileges beyond what the
// service already has and no external dependencies:
//  1. find the LISTEN entry for addr in /proc/net/tcp{,6} and read its inode
//  2. look for socket:[inode] among /proc/<pid>/fd/*
//
// A false return simply degrades the reported state; it never blocks a healthy
// setup, because callers treat "unknown" as not-owned only for diagnostics.
func OwnsListener(pid int, addr string) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("parse addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	inodes, err := listenInodes(host, port)
	if err != nil {
		return false, err
	}
	if len(inodes) == 0 {
		return false, nil
	}
	return pidHoldsAnyInode(pid, inodes)
}

// listenInodes returns the socket inodes listening on host:port.
func listenInodes(host string, port int) (map[string]struct{}, error) {
	want := net.ParseIP(host)
	out := map[string]struct{}{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		inodes, err := scanProcNet(f, want, port)
		if err != nil {
			if os.IsNotExist(err) {
				continue // no IPv6 stack, etc.
			}
			return nil, err
		}
		for i := range inodes {
			out[i] = struct{}{}
		}
	}
	return out, nil
}

// procNetListenState is TCP_LISTEN in /proc/net/tcp's hex state column.
const procNetListenState = "0A"

func scanProcNet(path string, wantIP net.IP, wantPort int) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	found := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// local_address is col 1, state col 3, inode col 9
		if len(fields) < 10 || fields[3] != procNetListenState {
			continue
		}
		ip, port, err := parseHexAddr(fields[1])
		if err != nil || port != wantPort {
			continue
		}
		// A wildcard listener (0.0.0.0 / ::) serves the requested IP too.
		if wantIP != nil && !ip.IsUnspecified() && !ip.Equal(wantIP) {
			continue
		}
		found[fields[9]] = struct{}{}
	}
	return found, sc.Err()
}

// parseHexAddr decodes /proc/net/tcp's "0100007F:1F90" address form.
func parseHexAddr(s string) (net.IP, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("malformed address %q", s)
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, err
	}
	port64, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return nil, 0, err
	}
	// Each 4-byte group is little-endian.
	ip := make(net.IP, len(raw))
	for i := 0; i+4 <= len(raw); i += 4 {
		ip[i+0], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i+0]
	}
	return ip, int(port64), nil
}

// pidHoldsAnyInode reports whether pid has any of these socket inodes open.
func pidHoldsAnyInode(pid int, inodes map[string]struct{}) (bool, error) {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		// Process gone, or we cannot introspect it.
		return false, nil
	}
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		inode, ok := strings.CutPrefix(link, "socket:[")
		if !ok {
			continue
		}
		inode = strings.TrimSuffix(inode, "]")
		if _, hit := inodes[inode]; hit {
			return true, nil
		}
	}
	return false, nil
}
