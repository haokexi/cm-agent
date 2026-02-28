package agentinfo

import "testing"

import "github.com/prometheus/client_golang/prometheus"

func TestCollectorIncludesAgentVersionLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(New("v1.2.3"))

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var found bool
	for _, mf := range mfs {
		if mf.GetName() != MetricName {
			continue
		}
		found = true
		if len(mf.GetMetric()) == 0 {
			t.Fatalf("%s has no samples", MetricName)
		}
		labels := mf.GetMetric()[0].GetLabel()
		hasVersion := false
		for _, lp := range labels {
			if lp.GetName() == "agent_version" && lp.GetValue() == "v1.2.3" {
				hasVersion = true
				break
			}
		}
		if !hasVersion {
			t.Fatalf("%s missing agent_version label", MetricName)
		}
	}
	if !found {
		t.Fatalf("metric %s not found", MetricName)
	}
}
