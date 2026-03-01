package main

import (
	"strings"
	"testing"
)

func TestParseLabelsOK(t *testing.T) {
	got, err := parseLabels([]string{"env=prod", "region=cn_hz_1"})
	if err != nil {
		t.Fatalf("parseLabels() error = %v", err)
	}
	if got["env"] != "prod" {
		t.Fatalf("env label mismatch: %q", got["env"])
	}
	if got["region"] != "cn_hz_1" {
		t.Fatalf("region label mismatch: %q", got["region"])
	}
}

func TestParseLabelsRejectInvalidKey(t *testing.T) {
	_, err := parseLabels([]string{"1bad=prod"})
	if err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestParseLabelsRejectLongValue(t *testing.T) {
	_, err := parseLabels([]string{"env=" + strings.Repeat("a", 257)})
	if err == nil {
		t.Fatal("expected long value error")
	}
}

func TestParseLabelsRejectDuplicateKey(t *testing.T) {
	_, err := parseLabels([]string{"env=prod", "env=staging"})
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
}

func TestIsManagedLabelKeyIgnored(t *testing.T) {
	if !isManagedLabelKeyIgnored("agent_version") {
		t.Fatal("agent_version should be ignored in managed labels")
	}
	if isManagedLabelKeyIgnored("tenant_id") {
		t.Fatal("tenant_id should not be ignored in managed labels")
	}
}
