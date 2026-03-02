package probe

import "testing"

func TestResolveProbeIPsFromLiterals(t *testing.T) {
	ipv4, ipv6 := resolveProbeIPs("icmp", "1.2.3.4")
	if ipv4 != "1.2.3.4" || ipv6 != "" {
		t.Fatalf("icmp ipv4 literal parsed wrong: ipv4=%q ipv6=%q", ipv4, ipv6)
	}

	ipv4, ipv6 = resolveProbeIPs("icmp", "2001:db8::1")
	if ipv4 != "" || ipv6 == "" {
		t.Fatalf("icmp ipv6 literal parsed wrong: ipv4=%q ipv6=%q", ipv4, ipv6)
	}
}

func TestResolveProbeIPsForTCPHostPortLiterals(t *testing.T) {
	ipv4, ipv6 := resolveProbeIPs("tcp_connect", "8.8.8.8:443")
	if ipv4 != "8.8.8.8" || ipv6 != "" {
		t.Fatalf("tcp ipv4 host:port parsed wrong: ipv4=%q ipv6=%q", ipv4, ipv6)
	}

	ipv4, ipv6 = resolveProbeIPs("tcp_connect", "[2001:db8::2]:8443")
	if ipv4 != "" || ipv6 == "" {
		t.Fatalf("tcp ipv6 host:port parsed wrong: ipv4=%q ipv6=%q", ipv4, ipv6)
	}
}
