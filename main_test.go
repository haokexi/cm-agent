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

func TestApplyDefaultHostIPLabelsFillsMissing(t *testing.T) {
	labels := map[string]string{"env": "prod"}
	applyDefaultHostIPLabels(labels, "10.0.0.2", "2001:db8::2")
	if labels["ipv4"] != "10.0.0.2" {
		t.Fatalf("ipv4 mismatch: %q", labels["ipv4"])
	}
	if labels["ipv6"] != "2001:db8::2" {
		t.Fatalf("ipv6 mismatch: %q", labels["ipv6"])
	}
}

func TestApplyDefaultHostIPLabelsKeepsManualOverride(t *testing.T) {
	labels := map[string]string{
		"ipv4": "203.0.113.10",
		"ipv6": "2001:db8::1",
	}
	applyDefaultHostIPLabels(labels, "10.0.0.2", "2001:db8::2")
	if labels["ipv4"] != "203.0.113.10" {
		t.Fatalf("manual ipv4 should win, got %q", labels["ipv4"])
	}
	if labels["ipv6"] != "2001:db8::1" {
		t.Fatalf("manual ipv6 should win, got %q", labels["ipv6"])
	}
}

func TestApplyDefaultHostIPLabelsFillsBlankManualValue(t *testing.T) {
	labels := map[string]string{
		"ipv4": "  ",
	}
	applyDefaultHostIPLabels(labels, "10.0.0.2", "")
	if labels["ipv4"] != "10.0.0.2" {
		t.Fatalf("blank manual ipv4 should be replaced, got %q", labels["ipv4"])
	}
}
