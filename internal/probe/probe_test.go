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

func TestNormalizeICMPEchoCount(t *testing.T) {
	if got := normalizeICMPEchoCount(0); got != defaultICMPEchoCount {
		t.Fatalf("expected default echo count %d, got %d", defaultICMPEchoCount, got)
	}
	if got := normalizeICMPEchoCount(3); got != 3 {
		t.Fatalf("expected echo count 3, got %d", got)
	}
	if got := normalizeICMPEchoCount(999); got != maxICMPEchoCount {
		t.Fatalf("expected clamped echo count %d, got %d", maxICMPEchoCount, got)
	}
}

func TestPingResultLossPercent(t *testing.T) {
	res := pingResult{Sent: 5, Received: 3}
	if got := res.LossPercent(); got != 40 {
		t.Fatalf("expected loss 40, got %v", got)
	}

	res = pingResult{Sent: 0, Received: 0}
	if got := res.LossPercent(); got != 0 {
		t.Fatalf("expected loss 0 for empty sample, got %v", got)
	}
}
