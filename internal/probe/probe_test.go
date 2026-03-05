package probe

import "testing"

func TestNormalizeIPProtocol(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "ipv4", want: "ipv4"},
		{in: "ip4", want: "ipv4"},
		{in: "ipv6", want: "ipv6"},
		{in: "ip6", want: "ipv6"},
		{in: "auto", want: "auto"},
		{in: "", want: "auto"},
		{in: "unknown", want: "auto"},
	}

	for _, tt := range tests {
		if got := normalizeIPProtocol(tt.in); got != tt.want {
			t.Fatalf("normalizeIPProtocol(%q)=%q want=%q", tt.in, got, tt.want)
		}
	}
}
