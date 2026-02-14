package convert

import (
	"math"
	"sort"
	"strconv"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"

	"cm-agent/internal/remotewrite"
)

type Stats struct {
	Series         int
	DroppedSeries  int
	DroppedSamples int
}

// BaseLabels returns a stable list of labels that will be applied to every time series.
// The caller should pass job/instance plus any extra labels used for routing/tenancy.
func BaseLabels(job, instance string, extra map[string]string) []remotewrite.Label {
	m := make(map[string]string, 2+len(extra))
	if job != "" {
		m["job"] = job
	}
	if instance != "" {
		m["instance"] = instance
	}
	for k, v := range extra {
		if k == "" || k == "__name__" {
			continue
		}
		m[k] = v
	}
	return labelsFromMap(m)
}

// ToWriteRequests converts gathered MetricFamily data into remote_write requests.
// No local /metrics exposure is required; this mimics a "scrape -> remote_write" pipeline in-process.
func ToWriteRequests(
	mfs []*dto.MetricFamily,
	now time.Time,
	baseLabels []remotewrite.Label,
	maxSeriesPerRequest int,
) ([]prompb.WriteRequest, Stats, error) {
	if maxSeriesPerRequest <= 0 {
		maxSeriesPerRequest = 2000
	}

	tsMillis := now.UnixMilli()
	var (
		series []prompb.TimeSeries
		stats  Stats
	)

	for _, mf := range mfs {
		if mf == nil {
			continue
		}
		name := mf.GetName()
		if name == "" {
			continue
		}

		for _, m := range mf.GetMetric() {
			if m == nil {
				continue
			}
			switch mf.GetType() {
			case dto.MetricType_COUNTER:
				if m.Counter == nil {
					continue
				}
				v := m.Counter.GetValue()
				if !validFloat(v) {
					stats.DroppedSamples++
					continue
				}
				series = append(series, makeTS(name, m.GetLabel(), baseLabels, v, tsMillis))
			case dto.MetricType_GAUGE:
				if m.Gauge == nil {
					continue
				}
				v := m.Gauge.GetValue()
				if !validFloat(v) {
					stats.DroppedSamples++
					continue
				}
				series = append(series, makeTS(name, m.GetLabel(), baseLabels, v, tsMillis))
			case dto.MetricType_UNTYPED:
				if m.Untyped == nil {
					continue
				}
				v := m.Untyped.GetValue()
				if !validFloat(v) {
					stats.DroppedSamples++
					continue
				}
				series = append(series, makeTS(name, m.GetLabel(), baseLabels, v, tsMillis))
			case dto.MetricType_HISTOGRAM:
				h := m.GetHistogram()
				if h == nil {
					continue
				}
				// Buckets.
				for _, b := range h.GetBucket() {
					ub := b.GetUpperBound()
					le := formatFloatForLabel(ub)
					cnt := float64(b.GetCumulativeCount())
					if !validFloat(cnt) {
						stats.DroppedSamples++
						continue
					}
					lbls := appendLabel(m.GetLabel(), "le", le)
					series = append(series, makeTS(name+"_bucket", lbls, baseLabels, cnt, tsMillis))
				}
				// _sum and _count.
				sum := h.GetSampleSum()
				cnt := float64(h.GetSampleCount())
				if validFloat(sum) {
					series = append(series, makeTS(name+"_sum", m.GetLabel(), baseLabels, sum, tsMillis))
				} else {
					stats.DroppedSamples++
				}
				if validFloat(cnt) {
					series = append(series, makeTS(name+"_count", m.GetLabel(), baseLabels, cnt, tsMillis))
				} else {
					stats.DroppedSamples++
				}
			case dto.MetricType_SUMMARY:
				s := m.GetSummary()
				if s == nil {
					continue
				}
				// Quantiles.
				for _, q := range s.GetQuantile() {
					qq := q.GetQuantile()
					qv := q.GetValue()
					if !validFloat(qv) || !validFloat(qq) {
						stats.DroppedSamples++
						continue
					}
					lbls := appendLabel(m.GetLabel(), "quantile", formatFloatForLabel(qq))
					series = append(series, makeTS(name, lbls, baseLabels, qv, tsMillis))
				}
				// _sum and _count.
				sum := s.GetSampleSum()
				cnt := float64(s.GetSampleCount())
				if validFloat(sum) {
					series = append(series, makeTS(name+"_sum", m.GetLabel(), baseLabels, sum, tsMillis))
				} else {
					stats.DroppedSamples++
				}
				if validFloat(cnt) {
					series = append(series, makeTS(name+"_count", m.GetLabel(), baseLabels, cnt, tsMillis))
				} else {
					stats.DroppedSamples++
				}
			default:
				// Skip unknown/unsupported types.
				continue
			}
		}
	}

	stats.Series = len(series)

	// Batch into multiple WriteRequests.
	reqs := make([]prompb.WriteRequest, 0, (len(series)+maxSeriesPerRequest-1)/maxSeriesPerRequest)
	for i := 0; i < len(series); i += maxSeriesPerRequest {
		end := i + maxSeriesPerRequest
		if end > len(series) {
			end = len(series)
		}
		reqs = append(reqs, prompb.WriteRequest{Timeseries: series[i:end]})
	}
	return reqs, stats, nil
}

func makeTS(name string, metricLabels []*dto.LabelPair, baseLabels []remotewrite.Label, v float64, tsMillis int64) prompb.TimeSeries {
	labels := mergeLabels(name, metricLabels, baseLabels)
	return prompb.TimeSeries{
		Labels: labels,
		Samples: []prompb.Sample{{
			Value:     v,
			Timestamp: tsMillis,
		}},
	}
}

func mergeLabels(name string, metricLabels []*dto.LabelPair, baseLabels []remotewrite.Label) []prompb.Label {
	// Build as a map, but preserve "base labels override metric labels" so job/instance are stable.
	m := make(map[string]string, 1+len(metricLabels)+len(baseLabels))
	m["__name__"] = name
	for _, lp := range metricLabels {
		if lp == nil {
			continue
		}
		k := lp.GetName()
		if k == "" || k == "__name__" {
			continue
		}
		m[k] = lp.GetValue()
	}
	for _, bl := range baseLabels {
		if bl.Name == "" || bl.Name == "__name__" {
			continue
		}
		m[bl.Name] = bl.Value
	}
	return labelsFromMap(m)
}

func labelsFromMap(m map[string]string) []prompb.Label {
	out := make([]prompb.Label, 0, len(m))
	for k, v := range m {
		out = append(out, prompb.Label{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func appendLabel(src []*dto.LabelPair, k, v string) []*dto.LabelPair {
	// dto.LabelPair uses pointers; create a new instance without pulling in protobuf helpers.
	k2 := k
	v2 := v
	return append(src, &dto.LabelPair{Name: &k2, Value: &v2})
}

func validFloat(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func formatFloatForLabel(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	default:
		// Prometheus exposition uses a Go-like float format.
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
}
