package realm

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfigBytes(t *testing.T) {
	raw := strings.Join([]string{
		"[network]",
		"no_tcp = false",
		"use_udp = true",
		"ipv6_only = false",
		"",
		"# 备注: web 入口",
		"[[endpoints]]",
		`listen = "[::]:443"`,
		`remote = "1.2.3.4:8443"`,
		"",
		"# remark: api",
		"[[endpoints]]",
		`listen = "0.0.0.0:8080"`,
		`remote = "example.com:80"`,
		"",
	}, "\n")

	cfg, err := parseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfigBytes() error = %v", err)
	}
	if cfg.Network.NoTCP {
		t.Fatal("expected no_tcp=false")
	}
	if !cfg.Network.UseUDP {
		t.Fatal("expected use_udp=true")
	}
	if cfg.Network.IPv6Only {
		t.Fatal("expected ipv6_only=false")
	}
	if len(cfg.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(cfg.Endpoints))
	}
	if cfg.Endpoints[0].Remark != "web 入口" {
		t.Fatalf("unexpected first remark: %q", cfg.Endpoints[0].Remark)
	}
	if cfg.Endpoints[1].Remark != "api" {
		t.Fatalf("unexpected second remark: %q", cfg.Endpoints[1].Remark)
	}
}

func TestRenderConfigRoundTrip(t *testing.T) {
	input := Config{
		Network: NetworkConfig{
			NoTCP:    true,
			UseUDP:   false,
			IPv6Only: true,
		},
		Endpoints: []Endpoint{
			{
				Remark: "main",
				Listen: "[::]:9000",
				Remote: "127.0.0.1:9001",
			},
		},
	}

	payload, err := renderConfig(input)
	if err != nil {
		t.Fatalf("renderConfig() error = %v", err)
	}
	cfg, err := parseConfigBytes(payload)
	if err != nil {
		t.Fatalf("round-trip parse error = %v", err)
	}
	if !cfg.Network.NoTCP || cfg.Network.UseUDP || !cfg.Network.IPv6Only {
		t.Fatalf("unexpected network config after round-trip: %+v", cfg.Network)
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(cfg.Endpoints))
	}
	if cfg.Endpoints[0].Listen != input.Endpoints[0].Listen {
		t.Fatalf("unexpected listen value: %q", cfg.Endpoints[0].Listen)
	}
	if cfg.Endpoints[0].Remote != input.Endpoints[0].Remote {
		t.Fatalf("unexpected remote value: %q", cfg.Endpoints[0].Remote)
	}
}

func TestNormalizeConfigRejectsInvalidEndpoint(t *testing.T) {
	_, err := normalizeConfig(&Config{
		Endpoints: []Endpoint{
			{Listen: "bad", Remote: "1.2.3.4:80"},
		},
	})
	if err == nil {
		t.Fatal("expected invalid listen address error")
	}
}

func TestExtractPathsFromArgs(t *testing.T) {
	binPath, configFile := extractPathsFromArgs([]string{"/root/realm/realm", "-c", "/root/realm/config.toml"})
	if binPath != "/root/realm/realm" {
		t.Fatalf("unexpected binPath: %q", binPath)
	}
	if configFile != "/root/realm/config.toml" {
		t.Fatalf("unexpected configFile: %q", configFile)
	}
}

func TestSplitCommandLine(t *testing.T) {
	args, err := splitCommandLine(`/usr/local/bin/realm -c "/etc/realm/config.toml"`)
	if err != nil {
		t.Fatalf("splitCommandLine() error = %v", err)
	}
	want := []string{"/usr/local/bin/realm", "-c", "/etc/realm/config.toml"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("unexpected args: got=%v want=%v", args, want)
	}
}

func TestParseExecStartFromUnitFile(t *testing.T) {
	dir := t.TempDir()
	unitPath := filepath.Join(dir, "realm.service")
	content := strings.Join([]string{
		"[Unit]",
		"Description=Realm Proxy Service",
		"[Service]",
		`ExecStart=/root/realm/realm -c /root/realm/config.toml`,
		"",
	}, "\n")
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	args, err := parseExecStartFromUnitFile(unitPath)
	if err != nil {
		t.Fatalf("parseExecStartFromUnitFile() error = %v", err)
	}
	want := []string{"/root/realm/realm", "-c", "/root/realm/config.toml"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("unexpected args: got=%v want=%v", args, want)
	}
}
