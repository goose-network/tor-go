package socks5

import (
	"net"
	"testing"
)

// TestIsInternalIP mirrors tor_addr_is_internal_ (address.c:255) with
// for_listening=0. Each case is a C-reference rule.
func TestIsInternalIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		// rule is the C-reference comment for documentation.
		rule string
	}{
		// IPv4 internal ranges.
		{"0.0.0.0", true, "0/8"},
		{"0.1.2.3", true, "0/8"},
		{"10.0.0.1", true, "10/8"},
		{"10.255.255.255", true, "10/8"},
		{"127.0.0.1", true, "127/8 loopback"},
		{"127.255.255.254", true, "127/8 loopback"},
		{"100.64.0.1", true, "100.64/10 RFC6598"},
		{"100.127.255.255", true, "100.64/10 RFC6598"},
		{"100.63.255.255", false, "just below 100.64/10"},
		{"100.128.0.0", false, "just above 100.64/10"},
		{"169.254.0.1", true, "169.254/16 link-local"},
		{"169.254.255.255", true, "169.254/16 link-local"},
		{"169.253.255.255", false, "just below 169.254/16"},
		{"172.16.0.1", true, "172.16/12 private"},
		{"172.31.255.255", true, "172.16/12 private"},
		{"172.15.255.255", false, "just below 172.16/12"},
		{"172.32.0.0", false, "just above 172.16/12"},
		{"192.168.0.1", true, "192.168/16 private"},
		{"192.168.255.255", true, "192.168/16 private"},
		// IPv4 public ranges.
		{"1.1.1.1", false, "public"},
		{"8.8.8.8", false, "public"},
		{"11.0.0.1", false, "public (just above 10/8)"},
		{"128.31.0.34", false, "public (moria1)"},
		{"171.25.193.78", false, "public (maatuska)"},
		{"185.220.101.102", false, "public fallback"},
		// IPv6 internal ranges.
		{"::1", true, "::/127 loopback"},
		{"::", true, "::/127 loopback (zero is in ::/127)"},
		{"::2", false, "just above ::/127"},
		{"fc00::1", true, "fc00/7 RFC4193 ULA"},
		{"fdff:ffff::1", true, "fc00/7 RFC4193 ULA"},
		{"fe80::1", true, "fe80/10 link-local"},
		{"febf:ffff::1", true, "fe80/10 link-local"},
		{"fec0::1", true, "fec0/10 deprecated site-local"},
		{"feff:ffff::1", true, "fec0/10 top of range (mask 0xffc00000)"},
		{"ff00::1", false, "just above fe80/10 and fec0/10"},
		// IPv6 public.
		{"2001::1", false, "public IPv6"},
		{"2606:4700:4700::1111", false, "public IPv6 (Cloudflare)"},
		// IPv4-mapped IPv6 reduces to IPv4.
		{"::ffff:127.0.0.1", true, "IPv4-mapped 127/8 loopback"},
		{"::ffff:10.0.0.1", true, "IPv4-mapped 10/8"},
		{"::ffff:1.1.1.1", false, "IPv4-mapped public"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Errorf("net.ParseIP(%q) = nil", c.ip)
			continue
		}
		got := isInternalIP(ip)
		if got != c.want {
			t.Errorf("isInternalIP(%q) = %v, want %v (%s)", c.ip, got, c.want, c.rule)
		}
	}
}

// TestRejectPrivateTarget covers the hostname-local and IP-literal paths,
// mirroring tor_addr_hostname_is_local + the internal-IP check.
func TestRejectPrivateTarget(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Hostname-form local (tor_addr_hostname_is_local).
		{"localhost", true},
		{"LOCALHOST", true},
		{"Local", true},
		{"local", true},
		{"foo.local", true},
		{"FOO.LOCAL", true},
		// IP literals.
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"::1", true},
		{"fc00::1", true},
		// Public IP literals and hostnames are allowed (the exit resolves
		// hostnames and applies its own exit policy).
		{"1.1.1.1", false},
		{"128.31.0.34", false},
		{"example.com", false},
		{"sub.example.org", false},
		{"", false}, // empty handled elsewhere
	}
	for _, c := range cases {
		got := RejectPrivateTarget(c.host)
		if got != c.want {
			t.Errorf("RejectPrivateTarget(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
