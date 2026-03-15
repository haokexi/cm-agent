package realm

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestBuildListenCandidates(t *testing.T) {
	tests := []struct {
		listen string
		want   []string
	}{
		{listen: "0.0.0.0:8080", want: []string{"127.0.0.1:8080"}},
		{listen: "[::]:8443", want: []string{"[::1]:8443", "127.0.0.1:8443"}},
		{listen: "192.0.2.10:9000", want: []string{"192.0.2.10:9000"}},
	}

	for _, tt := range tests {
		got, err := buildListenCandidates(tt.listen)
		if err != nil {
			t.Fatalf("buildListenCandidates(%q) error = %v", tt.listen, err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("buildListenCandidates(%q) = %v, want %v", tt.listen, got, tt.want)
		}
	}
}

func TestTestRule(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	result := TestRule(context.Background(), RuleTestRequest{
		RequestID: "r1",
		Listen:    ln.Addr().String(),
		Remote:    ln.Addr().String(),
	})
	if !result.ListenReachable {
		t.Fatalf("expected listen reachable, got %#v", result)
	}
	if !result.RemoteReachable {
		t.Fatalf("expected remote reachable, got %#v", result)
	}
	if !result.Success {
		t.Fatalf("expected success, got %#v", result)
	}
}
