package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/node_exporter/collector"

	"cm-agent/internal/config"
	"cm-agent/internal/convert"
	"cm-agent/internal/probe"
	"cm-agent/internal/remotewrite"
	"cm-agent/internal/spool"
)

func main() {
	hostname, _ := os.Hostname()

	var (
		configPath = kingpin.Flag(
			"config.file",
			"Optional YAML config file path.",
		).Envar("CM_CONFIG_FILE").Default("").String()
		rwURL = kingpin.Flag(
			"remoteWrite.url",
			"VictoriaMetrics single-node remote_write endpoint, e.g. https://vm.example.com:8428/api/v1/write",
		).Envar("CM_REMOTE_WRITE_URL").Default("").String()
		rwBearer = kingpin.Flag(
			"remoteWrite.bearer-token",
			"Bearer token for remote_write (sent as Authorization: Bearer <token>).",
		).Envar("CM_REMOTE_WRITE_BEARER_TOKEN").Default("").String()
		timeout = kingpin.Flag(
			"remoteWrite.timeout",
			"HTTP timeout for a single remote_write request.",
		).Envar("CM_REMOTE_WRITE_TIMEOUT").Default("10s").Duration()
		maxSeriesPerReq = kingpin.Flag(
			"remoteWrite.max-series-per-request",
			"Max timeseries per request. Used to split large pushes.",
		).Envar("CM_REMOTE_WRITE_MAX_SERIES_PER_REQUEST").Default("2000").Int()
		spoolDir = kingpin.Flag(
			"remoteWrite.spool.dir",
			"Directory for remote_write disk spool.",
		).Envar("CM_REMOTE_WRITE_SPOOL_DIR").Default("./spool").String()
		spoolMaxBytes = kingpin.Flag(
			"remoteWrite.spool.max-bytes",
			"Disk spool cap in bytes. Oldest payloads are dropped when exceeded.",
		).Envar("CM_REMOTE_WRITE_SPOOL_MAX_BYTES").Default("104857600").Int64()
		spoolMaxFiles = kingpin.Flag(
			"remoteWrite.spool.max-files",
			"Max number of files in spool directory.",
		).Envar("CM_REMOTE_WRITE_SPOOL_MAX_FILES").Default("2000").Int()
		flushMaxFiles = kingpin.Flag(
			"remoteWrite.flush.max-files",
			"Max number of spooled payload files to replay per cycle.",
		).Envar("CM_REMOTE_WRITE_FLUSH_MAX_FILES").Default("200").Int()
		interval = kingpin.Flag(
			"scrape.interval",
			"Collection interval. This agent does not open a local /metrics endpoint.",
		).Envar("CM_SCRAPE_INTERVAL").Default("15s").Duration()

		job = kingpin.Flag(
			"job",
			"Prometheus job label.",
		).Envar("CM_JOB").Default("node").String()
		instance = kingpin.Flag(
			"instance",
			"Prometheus instance label. Defaults to hostname.",
		).Envar("CM_INSTANCE").Default(hostname).String()
		labelKVs = kingpin.Flag(
			"label",
			"Extra labels applied to all metrics, repeatable: --label key=value",
		).Envar("CM_LABELS").Strings()

		disableDefaultCollectors = kingpin.Flag(
			"collector.disable-defaults",
			"Disable all default node_exporter collectors; enable explicitly via --collector.<name> flags.",
		).Envar("CM_COLLECTOR_DISABLE_DEFAULTS").Default("false").Bool()
		collectorFilters = kingpin.Flag(
			"collector.filter",
			"Collect only a subset of collectors (repeatable). Example: --collector.filter=cpu --collector.filter=meminfo",
		).Envar("CM_COLLECTOR_FILTERS").Strings()

		logLevel = kingpin.Flag(
			"log.level",
			"Log level: debug, info, warn, error",
		).Envar("CM_LOG_LEVEL").Default("info").String()

		probeJob = kingpin.Flag(
			"probe.job",
			"Job label for blackbox-like probes.",
		).Envar("CM_PROBE_JOB").Default("blackbox").String()
		probeTimeout = kingpin.Flag(
			"probe.timeout",
			"Timeout per probe (icmp or tcp).",
		).Envar("CM_PROBE_TIMEOUT").Default("2s").Duration()
		probeICMP = kingpin.Flag(
			"probe.icmp",
			"ICMP ping targets, repeatable (host or ip).",
		).Envar("CM_PROBE_ICMP").Strings()
		probeTCP = kingpin.Flag(
			"probe.tcp",
			"TCP connect targets, repeatable (host:port).",
		).Envar("CM_PROBE_TCP").Strings()
	)

	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	loadedCfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(2)
	}
	applyConfigDefaults(
		loadedCfg,
		rwURL, rwBearer, timeout, maxSeriesPerReq,
		spoolDir, spoolMaxBytes, spoolMaxFiles, flushMaxFiles,
		interval, job, instance, labelKVs, disableDefaultCollectors, collectorFilters, logLevel,
		probeJob, probeTimeout, probeICMP, probeTCP,
	)

	if strings.TrimSpace(*rwURL) == "" {
		fmt.Fprintln(os.Stderr, "missing required remoteWrite.url (or CM_REMOTE_WRITE_URL)")
		os.Exit(2)
	}
	if strings.TrimSpace(*rwBearer) == "" {
		fmt.Fprintln(os.Stderr, "missing required remoteWrite.bearer-token (or CM_REMOTE_WRITE_BEARER_TOKEN)")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(*logLevel),
	}))

	if *disableDefaultCollectors {
		collector.DisableDefaultCollectors()
	}

	extraLabels, err := parseLabels(*labelKVs)
	if err != nil {
		logger.Error("invalid --label", "err", err)
		os.Exit(2)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(promcollectors.NewGoCollector())
	reg.MustRegister(promcollectors.NewProcessCollector(promcollectors.ProcessCollectorOpts{}))

	nc, err := collector.NewNodeCollector(logger, *collectorFilters...)
	if err != nil {
		logger.Error("failed to init node_exporter collectors", "err", err)
		os.Exit(1)
	}
	reg.MustRegister(nc)

	internal := newInternalMetrics()
	reg.MustRegister(internal)

	rw := remotewrite.NewClient(remotewrite.Config{
		URL:                 *rwURL,
		BearerToken:         *rwBearer,
		Timeout:             *timeout,
		MaxSeriesPerRequest: *maxSeriesPerReq,
		UserAgent:           "cm-agent/0.1",
	})

	var diskSpool *spool.Spool
	if *spoolMaxBytes > 0 && strings.TrimSpace(*spoolDir) != "" {
		diskSpool, err = spool.New(*spoolDir, *spoolMaxBytes, *spoolMaxFiles)
		if err != nil {
			logger.Error("failed to init spool", "err", err)
			os.Exit(1)
		}
	}

	baseLabels := convert.BaseLabels(*job, *instance, extraLabels)
	probeLabels := make(map[string]string, len(extraLabels)+1)
	for k, v := range extraLabels {
		probeLabels[k] = v
	}
	probeLabels["probe_from"] = hostname
	baseProbeLabels := convert.BaseLabels(*probeJob, "", probeLabels)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Push immediately on startup.
	if _, err := flushSpool(ctx, logger, rw, diskSpool, *flushMaxFiles); err != nil {
		logger.Warn("initial spool flush failed", "err", err)
	}
	if err := collectAndPush(ctx, logger, reg, rw, diskSpool, baseLabels, internal); err != nil {
		logger.Warn("initial push failed", "err", err)
	}
	if err := collectAndPushProbes(ctx, logger, rw, diskSpool, baseProbeLabels, *probeTimeout, *probeICMP, *probeTCP); err != nil {
		logger.Warn("initial probe push failed", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return
		case <-ticker.C:
			if _, err := flushSpool(ctx, logger, rw, diskSpool, *flushMaxFiles); err != nil {
				logger.Warn("spool flush failed", "err", err)
			}
			if err := collectAndPush(ctx, logger, reg, rw, diskSpool, baseLabels, internal); err != nil {
				logger.Warn("push failed", "err", err)
			}
			if err := collectAndPushProbes(ctx, logger, rw, diskSpool, baseProbeLabels, *probeTimeout, *probeICMP, *probeTCP); err != nil {
				logger.Warn("probe push failed", "err", err)
			}
		}
	}
}

func collectAndPush(
	ctx context.Context,
	logger *slog.Logger,
	reg prometheus.Gatherer,
	rw *remotewrite.Client,
	diskSpool *spool.Spool,
	baseLabels []remotewrite.Label,
	internal *internalMetrics,
) error {
	start := time.Now()
	now := time.Now()

	mfs, err := reg.Gather()
	if err != nil {
		internal.setScrape(false, time.Since(start))
		return fmt.Errorf("gather: %w", err)
	}

	// Best-effort: update internal metrics even if conversion/push fails later.
	internal.setScrape(true, time.Since(start))

	reqs, stats, err := convert.ToWriteRequests(mfs, now, baseLabels, rw.MaxSeriesPerRequest())
	if err != nil {
		internal.setPush(false, 0, time.Since(start))
		return fmt.Errorf("convert: %w", err)
	}
	if stats.Series == 0 {
		internal.setPush(true, 0, time.Since(start))
		return nil
	}

	var pushed int
	pushStart := time.Now()
	for i := range reqs {
		payload, n, err := rw.Encode(&reqs[i])
		if err != nil {
			internal.setPush(false, pushed, time.Since(pushStart))
			return err
		}
		err = rw.PushCompressed(ctx, payload)
		if err != nil {
			queued := 0
			if diskSpool != nil {
				queued, _ = enqueuePayload(diskSpool, n, payload)
				for j := i + 1; j < len(reqs); j++ {
					p, s, encErr := rw.Encode(&reqs[j])
					if encErr != nil {
						continue
					}
					if qn, qErr := enqueuePayload(diskSpool, s, p); qErr == nil {
						queued += qn
					}
				}
			}
			internal.setPush(false, pushed, time.Since(pushStart))
			return fmt.Errorf("push failed (queued_series=%d): %w", queued, err)
		}
		pushed += n
	}
	internal.setPush(true, pushed, time.Since(pushStart))

	logger.Debug("push ok",
		"series_total", stats.Series,
		"series_pushed", pushed,
		"dropped_samples", stats.DroppedSamples,
		"dropped_series", stats.DroppedSeries,
	)

	return nil
}

func flushSpool(
	ctx context.Context,
	logger *slog.Logger,
	rw *remotewrite.Client,
	diskSpool *spool.Spool,
	maxFiles int,
) (int, error) {
	if diskSpool == nil || maxFiles <= 0 {
		return 0, nil
	}
	entries, total, err := diskSpool.List()
	if err != nil {
		return 0, fmt.Errorf("list spool: %w", err)
	}
	if len(entries) == 0 {
		return 0, nil
	}
	if len(entries) > maxFiles {
		entries = entries[:maxFiles]
	}

	flushed := 0
	for _, e := range entries {
		series, payload, err := diskSpool.Read(e.Path)
		if err != nil {
			logger.Warn("drop unreadable spool file", "path", e.Path, "err", err)
			_ = diskSpool.Delete(e.Path)
			continue
		}
		if err := rw.PushCompressed(ctx, payload); err != nil {
			return flushed, err
		}
		if err := diskSpool.Delete(e.Path); err != nil {
			return flushed, err
		}
		flushed += series
	}
	logger.Debug("flushed spool", "entries", len(entries), "series", flushed, "spool_bytes_before", total)
	return flushed, nil
}

func enqueuePayload(s *spool.Spool, series int, payload []byte) (int, error) {
	if s == nil || len(payload) == 0 {
		return 0, nil
	}
	if _, err := s.Add(series, payload); err != nil {
		return 0, err
	}
	return series, nil
}

func applyConfigDefaults(
	cfg *config.Config,
	rwURL, rwBearer *string,
	timeout *time.Duration,
	maxSeriesPerReq *int,
	spoolDir *string,
	spoolMaxBytes *int64,
	spoolMaxFiles, flushMaxFiles *int,
	interval *time.Duration,
	job, instance *string,
	labelKVs *[]string,
	disableDefaultCollectors *bool,
	collectorFilters *[]string,
	logLevel *string,
	probeJob *string,
	probeTimeout *time.Duration,
	probeICMP *[]string,
	probeTCP *[]string,
) {
	if cfg == nil {
		return
	}
	// Config only fills empty/unset-like values; flags/env remain highest priority.
	if *rwURL == "" && cfg.RemoteWrite.URL != "" {
		*rwURL = cfg.RemoteWrite.URL
	}
	if *rwBearer == "" && cfg.RemoteWrite.BearerToken != "" {
		*rwBearer = cfg.RemoteWrite.BearerToken
	}
	if *timeout == 10*time.Second && cfg.RemoteWrite.Timeout.Duration > 0 {
		*timeout = cfg.RemoteWrite.Timeout.Duration
	}
	if *maxSeriesPerReq == 2000 && cfg.RemoteWrite.MaxSeriesPerRequest > 0 {
		*maxSeriesPerReq = cfg.RemoteWrite.MaxSeriesPerRequest
	}
	if *spoolDir == "./spool" && cfg.RemoteWrite.Spool.Dir != "" {
		*spoolDir = cfg.RemoteWrite.Spool.Dir
	}
	if *spoolMaxBytes == 104857600 && cfg.RemoteWrite.Spool.MaxBytes > 0 {
		*spoolMaxBytes = cfg.RemoteWrite.Spool.MaxBytes
	}
	if *spoolMaxFiles == 2000 && cfg.RemoteWrite.Spool.MaxFiles > 0 {
		*spoolMaxFiles = cfg.RemoteWrite.Spool.MaxFiles
	}
	if *flushMaxFiles == 200 && cfg.RemoteWrite.Flush.MaxFiles > 0 {
		*flushMaxFiles = cfg.RemoteWrite.Flush.MaxFiles
	}
	if *interval == 15*time.Second && cfg.Scrape.Interval.Duration > 0 {
		*interval = cfg.Scrape.Interval.Duration
	}
	if *job == "node" && cfg.Labels.Job != "" {
		*job = cfg.Labels.Job
	}
	if cfg.Labels.Instance != "" {
		*instance = cfg.Labels.Instance
	}
	if len(*labelKVs) == 0 && len(cfg.Labels.Extra) > 0 {
		out := make([]string, 0, len(cfg.Labels.Extra))
		for k, v := range cfg.Labels.Extra {
			out = append(out, k+"="+v)
		}
		*labelKVs = out
	}
	if !*disableDefaultCollectors && cfg.Collectors.DisableDefaults {
		*disableDefaultCollectors = true
	}
	if len(*collectorFilters) == 0 && len(cfg.Collectors.Filters) > 0 {
		*collectorFilters = append(*collectorFilters, cfg.Collectors.Filters...)
	}
	if *logLevel == "info" && cfg.Log.Level != "" {
		*logLevel = cfg.Log.Level
	}

	if *probeJob == "blackbox" && cfg.Probes.Job != "" {
		*probeJob = cfg.Probes.Job
	}
	if *probeTimeout == 2*time.Second && cfg.Probes.Timeout.Duration > 0 {
		*probeTimeout = cfg.Probes.Timeout.Duration
	}
	if len(*probeICMP) == 0 && len(cfg.Probes.ICMP) > 0 {
		*probeICMP = append(*probeICMP, cfg.Probes.ICMP...)
	}
	if len(*probeTCP) == 0 && len(cfg.Probes.TCP) > 0 {
		*probeTCP = append(*probeTCP, cfg.Probes.TCP...)
	}
}

func collectAndPushProbes(
	ctx context.Context,
	logger *slog.Logger,
	rw *remotewrite.Client,
	diskSpool *spool.Spool,
	baseProbeLabels []remotewrite.Label,
	timeout time.Duration,
	icmpTargets []string,
	tcpTargets []string,
) error {
	if len(icmpTargets) == 0 && len(tcpTargets) == 0 {
		return nil
	}
	probeReg := prometheus.NewRegistry()
	probeReg.MustRegister(probe.NewCollector(probe.Config{
		Logger:  logger,
		Timeout: timeout,
		ICMP:    icmpTargets,
		TCP:     tcpTargets,
	}))

	mfs, err := probeReg.Gather()
	if err != nil {
		return fmt.Errorf("probe gather: %w", err)
	}
	reqs, _, err := convert.ToWriteRequests(mfs, time.Now(), baseProbeLabels, rw.MaxSeriesPerRequest())
	if err != nil {
		return fmt.Errorf("probe convert: %w", err)
	}

	for i := range reqs {
		payload, n, err := rw.Encode(&reqs[i])
		if err != nil {
			return err
		}
		if err := rw.PushCompressed(ctx, payload); err != nil {
			if diskSpool != nil {
				_, _ = enqueuePayload(diskSpool, n, payload)
				for j := i + 1; j < len(reqs); j++ {
					p, s, encErr := rw.Encode(&reqs[j])
					if encErr != nil {
						continue
					}
					_, _ = enqueuePayload(diskSpool, s, p)
				}
			}
			return err
		}
	}
	return nil
}

func parseLabels(kvs []string) (map[string]string, error) {
	out := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("expected key=value, got %q", kv)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "__name__" {
			return nil, errors.New("label __name__ is reserved")
		}
		out[k] = v
	}
	return out, nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// internalMetrics is a tiny set of self-observability metrics.
// Since this agent does not expose /metrics, these only exist via remote_write.
type internalMetrics struct {
	scrapeOK       *prometheus.GaugeVec
	scrapeDuration prometheus.Gauge

	pushOK       prometheus.Gauge
	pushSeries   prometheus.Gauge
	pushDuration prometheus.Gauge
}

func newInternalMetrics() *internalMetrics {
	return &internalMetrics{
		scrapeOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cm_agent_scrape_success",
			Help: "Whether the last in-process gather succeeded (1) or failed (0).",
		}, []string{"phase"}),
		scrapeDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cm_agent_scrape_duration_seconds",
			Help: "Time spent gathering metrics from in-process collectors.",
		}),
		pushOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cm_agent_remote_write_success",
			Help: "Whether the last remote_write push succeeded (1) or failed (0).",
		}),
		pushSeries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cm_agent_remote_write_series_pushed",
			Help: "Number of time series pushed in the last successful push (sum across requests).",
		}),
		pushDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cm_agent_remote_write_duration_seconds",
			Help: "Time spent pushing time series to remote_write endpoint (sum across requests).",
		}),
	}
}

func (m *internalMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.scrapeOK.Describe(ch)
	m.scrapeDuration.Describe(ch)
	m.pushOK.Describe(ch)
	m.pushSeries.Describe(ch)
	m.pushDuration.Describe(ch)
}

func (m *internalMetrics) Collect(ch chan<- prometheus.Metric) {
	m.scrapeOK.Collect(ch)
	m.scrapeDuration.Collect(ch)
	m.pushOK.Collect(ch)
	m.pushSeries.Collect(ch)
	m.pushDuration.Collect(ch)
}

func (m *internalMetrics) setScrape(ok bool, d time.Duration) {
	if ok {
		m.scrapeOK.WithLabelValues("gather").Set(1)
	} else {
		m.scrapeOK.WithLabelValues("gather").Set(0)
	}
	m.scrapeDuration.Set(d.Seconds())
}

func (m *internalMetrics) setPush(ok bool, series int, d time.Duration) {
	if ok {
		m.pushOK.Set(1)
		m.pushSeries.Set(float64(series))
	} else {
		m.pushOK.Set(0)
	}
	m.pushDuration.Set(d.Seconds())
}

// Ensure we import dto for go mod to keep client_model pinned; dto is also used in internal/convert tests.
var _ = dto.MetricFamily{}
