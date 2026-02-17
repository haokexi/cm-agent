package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/node_exporter/collector"

	"cm-agent/internal/agentinfo"
	"cm-agent/internal/config"
	"cm-agent/internal/convert"
	"cm-agent/internal/probe"
	"cm-agent/internal/remotewrite"
	"cm-agent/internal/spool"
	"cm-agent/internal/terminal"
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
		nodeID = kingpin.Flag(
			"node-id",
			"Optional node id label. If set, injects label node_id=<id> unless already provided via --label. Used by server-side PromQL matching.",
		).Envar("CM_NODE_ID").Default("").String()

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

		terminalEnabled = kingpin.Flag(
			"terminal.enabled",
			"Enable reverse web terminal agent.",
		).Envar("CM_TERMINAL_ENABLED").Default("false").Bool()
		terminalServer = kingpin.Flag(
			"terminal.server",
			"Terminal server base address (scheme+host[:port][+optional path]). If set and ws URLs are empty, paths are derived as /cloudmonitor/terminal/agent/{control,terminal}/ws.",
		).Envar("CM_TERMINAL_SERVER").Default("").String()
		terminalContextPath = kingpin.Flag(
			"terminal.context-path",
			"Server context path (default /cloudmonitor). Used when deriving terminal ws URLs from --terminal.server.",
		).Envar("CM_TERMINAL_CONTEXT_PATH").Default("/cloudmonitor").String()
		terminalAgentToken = kingpin.Flag(
			"terminal.agent-token",
			"Long-lived token for control channel auth.",
		).Envar("CM_TERMINAL_AGENT_TOKEN").Default("").String()
		terminalDialTimeout = kingpin.Flag(
			"terminal.dial-timeout",
			"Terminal WS dial timeout.",
		).Envar("CM_TERMINAL_DIAL_TIMEOUT").Default("10s").Duration()
		terminalPingInterval = kingpin.Flag(
			"terminal.ping-interval",
			"Control/session WS keepalive ping interval.",
		).Envar("CM_TERMINAL_PING_INTERVAL").Default("30s").Duration()
		terminalTLSInsecure = kingpin.Flag(
			"terminal.tls-insecure-skip-verify",
			"Skip TLS verification for terminal/control websocket connections.",
		).Envar("CM_TERMINAL_TLS_INSECURE_SKIP_VERIFY").Default("false").Bool()
		terminalShell = kingpin.Flag(
			"terminal.shell",
			"Shell executable for terminal sessions.",
		).Envar("CM_TERMINAL_SHELL").Default("/bin/bash").String()
		terminalShellArgs = kingpin.Flag(
			"terminal.shell-arg",
			"Shell args, repeatable.",
		).Envar("CM_TERMINAL_SHELL_ARGS").Strings()
		terminalTerm = kingpin.Flag(
			"terminal.term",
			"TERM value exported to terminal sessions (for TUIs like top/vim).",
		).Envar("CM_TERMINAL_TERM").Default("xterm-256color").String()
		terminalMaxSessions = kingpin.Flag(
			"terminal.max-sessions",
			"Max concurrent terminal sessions on this agent.",
		).Envar("CM_TERMINAL_MAX_SESSIONS").Default("1").Int()
		terminalMaxDuration = kingpin.Flag(
			"terminal.max-duration",
			"Max duration per terminal session (0 to disable).",
		).Envar("CM_TERMINAL_MAX_DURATION").Default("0s").Duration()
		terminalIdleTimeout = kingpin.Flag(
			"terminal.idle-timeout",
			"Idle timeout per terminal session (0 to disable).",
		).Envar("CM_TERMINAL_IDLE_TIMEOUT").Default("0s").Duration()
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
		terminalEnabled, terminalServer, terminalContextPath, terminalAgentToken,
		terminalDialTimeout, terminalPingInterval, terminalTLSInsecure, terminalShell, terminalShellArgs, terminalTerm,
		terminalMaxSessions, terminalMaxDuration, terminalIdleTimeout,
	)

	var derivedTerminalControlWSURL, derivedTerminalWSURL string
	if *terminalEnabled {
		if strings.TrimSpace(*terminalServer) == "" {
			fmt.Fprintln(os.Stderr, "terminal enabled but missing --terminal.server (or CM_TERMINAL_SERVER / config.terminal.server)")
			os.Exit(2)
		}
		c, t, err := deriveTerminalWSURLs(*terminalServer, *terminalContextPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "derive terminal ws urls: %v\n", err)
			os.Exit(2)
		}
		derivedTerminalControlWSURL = c
		derivedTerminalWSURL = t
	}

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

	staticExtraLabels, err := parseLabels(*labelKVs)
	if err != nil {
		logger.Error("invalid --label", "err", err)
		os.Exit(2)
	}
	// Convenience: ensure node_id label exists when user provides --node-id.
	// Server-side status/usage queries rely on node_id="<id>" to map metrics to nodes.
	if strings.TrimSpace(*nodeID) != "" {
		if _, ok := staticExtraLabels["node_id"]; !ok {
			staticExtraLabels["node_id"] = strings.TrimSpace(*nodeID)
		}
	}
	// Convenience: if node_id isn't set, derive it from install token "<node_id>:<secret>".
	if _, ok := staticExtraLabels["node_id"]; !ok {
		if nid := parseNodeIDFromInstallToken(*terminalAgentToken); nid != "" {
			staticExtraLabels["node_id"] = nid
		}
	}
	managedLabels := newManagedLabelState()
	managedProbes := newManagedProbeState()

	buildLabelSets := func() (base []remotewrite.Label, probe []remotewrite.Label) {
		merged := cloneLabels(staticExtraLabels)
		for k, v := range managedLabels.Snapshot() {
			// Keep static node_id stable for server-side node matching.
			if k == "node_id" {
				if _, exists := staticExtraLabels["node_id"]; exists {
					continue
				}
			}
			merged[k] = v
		}

		base = convert.BaseLabels(*job, *instance, merged)
		probeExtra := make(map[string]string, len(merged)+1)
		for k, v := range merged {
			probeExtra[k] = v
		}
		probeExtra["probe_from"] = hostname
		probe = convert.BaseLabels(*probeJob, "", probeExtra)
		return base, probe
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
	reg.MustRegister(agentinfo.New())

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *terminalEnabled {
		go func() {
			err := terminal.RunAgent(ctx, terminal.AgentConfig{
				Logger:                logger.With("component", "terminal-control"),
				Enabled:               *terminalEnabled,
				ControlWSURL:          derivedTerminalControlWSURL,
				TerminalWSURL:         derivedTerminalWSURL,
				AgentToken:            *terminalAgentToken,
				DialTimeout:           *terminalDialTimeout,
				PingInterval:          *terminalPingInterval,
				TLSInsecureSkipVerify: *terminalTLSInsecure,
				Shell:                 *terminalShell,
				ShellArgs:             *terminalShellArgs,
				Term:                  *terminalTerm,
				MaxSessions:           *terminalMaxSessions,
				MaxDuration:           *terminalMaxDuration,
				IdleTimeout:           *terminalIdleTimeout,
				OnSyncLabels: func(labels map[string]string, version int64) error {
					normalized := make(map[string]string, len(labels))
					for k, v := range labels {
						k = strings.TrimSpace(k)
						v = strings.TrimSpace(v)
						if err := validateLabelKV(k, v); err != nil {
							return err
						}
						normalized[k] = v
					}
					managedLabels.Apply(normalized, version)
					return nil
				},
				OnSyncProbes: func(rules []terminal.ProbeRule, version int64) error {
					normalized := normalizeManagedProbeRules(rules, *probeTimeout, logger)
					managedProbes.Apply(normalized, version)
					return nil
				},
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("terminal agent exited", "err", err)
			}
		}()
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Push immediately on startup.
	if _, err := flushSpool(ctx, logger, rw, diskSpool, *flushMaxFiles); err != nil {
		logger.Warn("initial spool flush failed", "err", err)
	}
	baseLabels, baseProbeLabels := buildLabelSets()
	if err := collectAndPush(ctx, logger, reg, rw, diskSpool, baseLabels, internal); err != nil {
		logger.Warn("initial push failed", "err", err)
	}
	if err := collectAndPushProbes(
		ctx, logger, rw, diskSpool, baseProbeLabels,
		*probeTimeout, *probeICMP, *probeTCP, managedProbes.DueTargets(time.Now()),
	); err != nil {
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
			baseLabels, baseProbeLabels := buildLabelSets()
			if err := collectAndPush(ctx, logger, reg, rw, diskSpool, baseLabels, internal); err != nil {
				logger.Warn("push failed", "err", err)
			}
			if err := collectAndPushProbes(
				ctx, logger, rw, diskSpool, baseProbeLabels,
				*probeTimeout, *probeICMP, *probeTCP, managedProbes.DueTargets(time.Now()),
			); err != nil {
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

type managedLabelState struct {
	mu      sync.RWMutex
	labels  map[string]string
	version int64
}

type managedProbeRule struct {
	RuleID     string
	Module     string
	Target     string
	IPProtocol string
	Interval   time.Duration
	Timeout    time.Duration
}

type managedProbeState struct {
	mu      sync.Mutex
	rules   map[string]managedProbeRule
	lastRun map[string]time.Time
	version int64
}

func newManagedProbeState() *managedProbeState {
	return &managedProbeState{
		rules:   make(map[string]managedProbeRule),
		lastRun: make(map[string]time.Time),
	}
}

func (s *managedProbeState) Apply(rules []managedProbeRule, version int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version > 0 && s.version > 0 && version < s.version {
		return
	}

	nextRules := make(map[string]managedProbeRule, len(rules))
	nextLastRun := make(map[string]time.Time, len(rules))
	for _, rule := range rules {
		if strings.TrimSpace(rule.RuleID) == "" {
			continue
		}
		nextRules[rule.RuleID] = rule
		if t, ok := s.lastRun[rule.RuleID]; ok {
			nextLastRun[rule.RuleID] = t
		}
	}
	s.rules = nextRules
	s.lastRun = nextLastRun
	if version > 0 {
		s.version = version
	}
}

func (s *managedProbeState) DueTargets(now time.Time) []probe.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rules) == 0 {
		return nil
	}
	var out []probe.Target
	for rid, rule := range s.rules {
		interval := rule.Interval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		last, ok := s.lastRun[rid]
		if ok && now.Sub(last) < interval {
			continue
		}
		s.lastRun[rid] = now
		out = append(out, probe.Target{
			Module:     rule.Module,
			Instance:   rule.Target,
			IPProtocol: rule.IPProtocol,
			RuleID:     rid,
			Timeout:    rule.Timeout,
		})
	}
	return out
}

func normalizeManagedProbeRules(in []terminal.ProbeRule, defaultTimeout time.Duration, logger *slog.Logger) []managedProbeRule {
	if logger == nil {
		logger = slog.Default()
	}
	var out []managedProbeRule
	for _, raw := range in {
		if !raw.Enabled {
			continue
		}
		rid := strings.TrimSpace(raw.RuleID)
		if rid == "" {
			logger.Warn("ignore probe rule with empty id")
			continue
		}
		module := strings.TrimSpace(strings.ToLower(raw.Module))
		switch module {
		case "icmp":
			// keep
		case "tcp", "tcp_connect":
			module = "tcp_connect"
		default:
			logger.Warn("ignore probe rule with invalid module", "rule_id", rid, "module", raw.Module)
			continue
		}
		target := strings.TrimSpace(raw.Target)
		if target == "" {
			logger.Warn("ignore probe rule with empty target", "rule_id", rid)
			continue
		}

		ipProtocol := "auto"
		if module == "icmp" {
			ipProtocol = normalizeProbeIPProtocol(raw.IPProtocol)
		}
		if module == "tcp_connect" {
			if _, _, err := net.SplitHostPort(target); err != nil {
				logger.Warn("ignore probe rule with invalid tcp target", "rule_id", rid, "target", target, "err", err)
				continue
			}
		}

		intervalSec := raw.IntervalSeconds
		if intervalSec <= 0 {
			intervalSec = 30
		}
		timeout := defaultTimeout
		if raw.TimeoutMs > 0 {
			timeout = time.Duration(raw.TimeoutMs) * time.Millisecond
		}
		if timeout <= 0 {
			timeout = 2 * time.Second
		}

		out = append(out, managedProbeRule{
			RuleID:     rid,
			Module:     module,
			Target:     target,
			IPProtocol: ipProtocol,
			Interval:   time.Duration(intervalSec) * time.Second,
			Timeout:    timeout,
		})
	}
	return out
}

func normalizeProbeIPProtocol(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ipv4", "ip4":
		return "ipv4"
	case "ipv6", "ip6":
		return "ipv6"
	default:
		return "auto"
	}
}

func newManagedLabelState() *managedLabelState {
	return &managedLabelState{
		labels: make(map[string]string),
	}
}

func (s *managedLabelState) Apply(labels map[string]string, version int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version > 0 && s.version > 0 && version < s.version {
		return
	}
	s.labels = cloneLabels(labels)
	if version > 0 {
		s.version = version
	}
}

func (s *managedLabelState) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneLabels(s.labels)
}

func cloneLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
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
	terminalEnabled *bool,
	terminalServer *string,
	terminalContextPath *string,
	terminalAgentToken *string,
	terminalDialTimeout *time.Duration,
	terminalPingInterval *time.Duration,
	terminalTLSInsecure *bool,
	terminalShell *string,
	terminalShellArgs *[]string,
	terminalTerm *string,
	terminalMaxSessions *int,
	terminalMaxDuration *time.Duration,
	terminalIdleTimeout *time.Duration,
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

	if !*terminalEnabled && cfg.Terminal.Enabled {
		*terminalEnabled = true
	}
	if *terminalServer == "" && cfg.Terminal.Server != "" {
		*terminalServer = cfg.Terminal.Server
	}
	if *terminalContextPath == "/cloudmonitor" && cfg.Terminal.ContextPath != "" {
		*terminalContextPath = cfg.Terminal.ContextPath
	}
	if *terminalAgentToken == "" && cfg.Terminal.AgentToken != "" {
		*terminalAgentToken = cfg.Terminal.AgentToken
	}
	if *terminalDialTimeout == 10*time.Second && cfg.Terminal.DialTimeout.Duration > 0 {
		*terminalDialTimeout = cfg.Terminal.DialTimeout.Duration
	}
	if *terminalPingInterval == 30*time.Second && cfg.Terminal.PingInterval.Duration > 0 {
		*terminalPingInterval = cfg.Terminal.PingInterval.Duration
	}
	if !*terminalTLSInsecure && cfg.Terminal.TLSInsecureSkipVerify {
		*terminalTLSInsecure = true
	}
	if *terminalShell == "/bin/bash" && cfg.Terminal.Shell != "" {
		*terminalShell = cfg.Terminal.Shell
	}
	if len(*terminalShellArgs) == 0 && len(cfg.Terminal.ShellArgs) > 0 {
		*terminalShellArgs = append(*terminalShellArgs, cfg.Terminal.ShellArgs...)
	}
	if *terminalTerm == "xterm-256color" && cfg.Terminal.Term != "" {
		*terminalTerm = cfg.Terminal.Term
	}
	if *terminalMaxSessions == 1 && cfg.Terminal.MaxSessions > 0 {
		*terminalMaxSessions = cfg.Terminal.MaxSessions
	}
	if *terminalMaxDuration == 0 && cfg.Terminal.MaxDuration.Duration > 0 {
		*terminalMaxDuration = cfg.Terminal.MaxDuration.Duration
	}
	if *terminalIdleTimeout == 0 && cfg.Terminal.IdleTimeout.Duration > 0 {
		*terminalIdleTimeout = cfg.Terminal.IdleTimeout.Duration
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
	managedTargets []probe.Target,
) error {
	if len(icmpTargets) == 0 && len(tcpTargets) == 0 && len(managedTargets) == 0 {
		return nil
	}
	probeReg := prometheus.NewRegistry()
	probeReg.MustRegister(probe.NewCollector(probe.Config{
		Logger:  logger,
		Timeout: timeout,
		ICMP:    icmpTargets,
		TCP:     tcpTargets,
		Targets: managedTargets,
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
		if err := validateLabelKV(k, v); err != nil {
			return nil, err
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate label key %q", k)
		}
		out[k] = v
	}
	return out, nil
}

var labelKeyRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateLabelKV(k, v string) error {
	if k == "__name__" {
		return errors.New("label __name__ is reserved")
	}
	if !labelKeyRegexp.MatchString(k) {
		return fmt.Errorf("invalid label key %q (must match [A-Za-z_][A-Za-z0-9_]*)", k)
	}
	if len([]byte(k)) > 256 {
		return fmt.Errorf("label key %q exceeds 256 bytes", k)
	}
	if v == "" {
		return fmt.Errorf("label value for %q cannot be empty", k)
	}
	if len([]byte(v)) > 256 {
		return fmt.Errorf("label value for %q exceeds 256 bytes", k)
	}
	if strings.Contains(v, ",") {
		return fmt.Errorf("label value for %q cannot contain comma", k)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("label value for %q contains control character", k)
		}
	}
	return nil
}

func parseNodeIDFromInstallToken(token string) string {
	t := strings.TrimSpace(token)
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "Bearer ") {
		t = strings.TrimSpace(strings.TrimPrefix(t, "Bearer "))
	}
	// Expect "<node_id>:<secret>".
	nodeID, _, ok := strings.Cut(t, ":")
	if !ok {
		return ""
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ""
	}
	for _, r := range nodeID {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return nodeID
}

func deriveTerminalWSURLs(serverBase, contextPath string) (control, terminal string, err error) {
	sb := strings.TrimSpace(serverBase)
	if sb == "" {
		return "", "", errors.New("terminal.server is empty")
	}
	// Accept host[:port] by auto-prepending http://
	if !strings.Contains(sb, "://") {
		sb = "http://" + sb
	}
	u, err := url.Parse(sb)
	if err != nil {
		return "", "", err
	}
	// Normalize scheme to ws/wss
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// ok
	default:
		return "", "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	// If serverBase has no path (or just "/"), use contextPath.
	basePath := strings.TrimSpace(u.Path)
	if basePath == "" || basePath == "/" {
		cp := strings.TrimSpace(contextPath)
		if cp == "" {
			cp = "/cloudmonitor"
		}
		if !strings.HasPrefix(cp, "/") {
			cp = "/" + cp
		}
		basePath = cp
	}
	basePath = strings.TrimRight(basePath, "/")
	u.RawQuery = ""
	u.Fragment = ""

	ctl := *u
	ctl.Path = path.Clean(basePath + "/terminal/agent/control/ws")
	term := *u
	term.Path = path.Clean(basePath + "/terminal/agent/terminal/ws")
	return ctl.String(), term.String(), nil
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
