package convert

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"
)

func TestHistogramConversion(t *testing.T) {
	name := "test_hist"
	mf := &dto.MetricFamily{
		Name: &name,
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Label: []*dto.LabelPair{
				lp("a", "b"),
			},
			Histogram: &dto.Histogram{
				SampleCount: u64(3),
				SampleSum:   f64(1.25),
				Bucket: []*dto.Bucket{
					{UpperBound: f64(0.1), CumulativeCount: u64(1)},
					{UpperBound: f64(1), CumulativeCount: u64(3)},
				},
			},
		}},
	}

	reqs, stats, err := ToWriteRequests(
		[]*dto.MetricFamily{mf},
		time.Unix(10, 0),
		BaseLabels("node", "h1", map[string]string{"site": "s1"}),
		1000,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if stats.Series != 4 {
		t.Fatalf("expected 4 series, got %d", stats.Series)
	}
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}

	got := index(reqs[0])
	mustHave(t, got, "test_hist_bucket|le=0.1")
	mustHave(t, got, "test_hist_bucket|le=1")
	mustHave(t, got, "test_hist_sum|")
	mustHave(t, got, "test_hist_count|")
}

func TestSummaryConversion(t *testing.T) {
	name := "test_sum"
	mf := &dto.MetricFamily{
		Name: &name,
		Type: dto.MetricType_SUMMARY.Enum(),
		Metric: []*dto.Metric{{
			Label: []*dto.LabelPair{lp("a", "b")},
			Summary: &dto.Summary{
				SampleCount: u64(7),
				SampleSum:   f64(3.14),
				Quantile: []*dto.Quantile{
					{Quantile: f64(0.5), Value: f64(1.0)},
				},
			},
		}},
	}

	reqs, stats, err := ToWriteRequests(
		[]*dto.MetricFamily{mf},
		time.Unix(10, 0),
		BaseLabels("node", "h1", nil),
		1000,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if stats.Series != 3 {
		t.Fatalf("expected 3 series, got %d", stats.Series)
	}
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}

	got := index(reqs[0])
	mustHave(t, got, "test_sum|quantile=0.5")
	mustHave(t, got, "test_sum_sum|")
	mustHave(t, got, "test_sum_count|")
}

func index(req prompb.WriteRequest) map[string]struct{} {
	out := make(map[string]struct{}, len(req.Timeseries))
	for _, ts := range req.Timeseries {
		name := labelValue(ts.Labels, "__name__")
		if name == "" {
			continue
		}
		if le := labelValue(ts.Labels, "le"); le != "" {
			out[name+"|le="+le] = struct{}{}
			continue
		}
		if q := labelValue(ts.Labels, "quantile"); q != "" {
			out[name+"|quantile="+q] = struct{}{}
			continue
		}
		out[name+"|"] = struct{}{}
	}
	return out
}

func labelValue(lbls []prompb.Label, k string) string {
	for _, l := range lbls {
		if l.Name == k {
			return l.Value
		}
	}
	return ""
}

func mustHave(t *testing.T, idx map[string]struct{}, key string) {
	t.Helper()
	if _, ok := idx[key]; !ok {
		t.Fatalf("missing series %q", key)
	}
}

func lp(k, v string) *dto.LabelPair {
	return &dto.LabelPair{Name: &k, Value: &v}
}

func u64(v uint64) *uint64   { return &v }
func f64(v float64) *float64 { return &v }
