package terminal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cm-agent/internal/netrate"
	"cm-agent/internal/selfupdate"

	"github.com/gorilla/websocket"
)

type AgentConfig struct {
	Logger *slog.Logger

	Enabled bool

	ControlWSURL  string // e.g. wss://server/api/agent/control/ws
	TerminalWSURL string // e.g. wss://server/api/agent/terminal/ws

	AgentToken string // long-lived agent auth for control channel

	DialTimeout           time.Duration
	PingInterval          time.Duration
	TLSInsecureSkipVerify bool

	Shell     string
	ShellArgs []string
	Term      string

	MaxSessions int
	MaxDuration time.Duration
	IdleTimeout time.Duration

	CurrentVersion    string
	UpdateRepo        string
	UpdateGitHubProxy string

	// OnSyncLabels applies dynamic labels pushed from server over control WS.
	OnSyncLabels func(map[string]string, int64) error
	// OnSyncProbes applies dynamic probe rules pushed from server over control WS.
	OnSyncProbes func([]ProbeRule, int64) error
}

func RunAgent(ctx context.Context, cfg AgentConfig) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.ControlWSURL) == "" || strings.TrimSpace(cfg.TerminalWSURL) == "" {
		return errors.New("terminal enabled but control/terminal ws url missing")
	}
	if strings.TrimSpace(cfg.AgentToken) == "" {
		return errors.New("terminal enabled but agent token missing")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 1
	}

	sem := make(chan struct{}, cfg.MaxSessions)

	// reconnect loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := runControlOnce(ctx, cfg, sem)
		if err == nil {
			// graceful exit
			return nil
		}
		cfg.Logger.Warn("control ws disconnected", "err", err)

		// backoff
		sleep := time.Second + time.Duration(rand.IntN(1000))*time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

func runControlOnce(ctx context.Context, cfg AgentConfig, sem chan struct{}) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: cfg.DialTimeout,
		Proxy:            http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify, //nolint:gosec
		},
	}
	hdr := map[string][]string{
		"Authorization": {"Bearer " + strings.TrimSpace(cfg.AgentToken)},
	}

	ws, _, err := dialer.DialContext(ctx, cfg.ControlWSURL, hdr)
	if err != nil {
		return fmt.Errorf("dial control ws: %w", err)
	}
	defer ws.Close()

	ws.SetReadLimit(1 << 20) // 1MiB control frame cap

	cfg.Logger.Info("terminal control connected")

	// Network rate streamer – lifecycle tied to this WS connection.
	rateStreamer := netrate.New(cfg.Logger.With("component", "netrate"))
	defer rateStreamer.Stop()

	// keepalive ping
	pingCtx, pingCancel := context.WithCancel(ctx)
	defer pingCancel()
	var wsWriteMu sync.Mutex
	writeJSON := func(v any) error {
		wsWriteMu.Lock()
		defer wsWriteMu.Unlock()
		return ws.WriteJSON(v)
	}
	var updating atomic.Bool

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(cfg.PingInterval)
		defer t.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-t.C:
				wsWriteMu.Lock()
				_ = ws.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
				wsWriteMu.Unlock()
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			pingCancel()
			wg.Wait()
			return ctx.Err()
		default:
		}

		mt, data, err := ws.ReadMessage()
		if err != nil {
			pingCancel()
			wg.Wait()
			return err
		}
		if mt != websocket.TextMessage && mt != websocket.BinaryMessage {
			continue
		}

		// Control messages are JSON (text). Some implementations might send text as binary.
		var msg ControlMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			cfg.Logger.Warn("invalid control message", "err", err)
			continue
		}
		switch msg.Type {
		case "sync_labels":
			if cfg.OnSyncLabels == nil {
				continue
			}
			if err := cfg.OnSyncLabels(msg.Labels, msg.Version); err != nil {
				cfg.Logger.Warn("apply sync labels failed", "err", err)
			} else {
				cfg.Logger.Info("applied sync labels", "labels", len(msg.Labels), "version", msg.Version)
			}
			continue
		case "sync_probes":
			if cfg.OnSyncProbes == nil {
				continue
			}
			if err := cfg.OnSyncProbes(msg.Probes, msg.Version); err != nil {
				cfg.Logger.Warn("apply sync probes failed", "err", err)
			} else {
				cfg.Logger.Info("applied sync probes", "rules", len(msg.Probes), "version", msg.Version)
			}
			continue
		case "open_terminal":
			// continue below
		case "network_test":
			go func(m ControlMessage) {
				res := runNetworkTestTask(ctx, cfg, m, func(p NetworkTestProgressMessage) {
					if err := writeJSON(p); err != nil {
						cfg.Logger.Warn("send network test progress failed", "test_id", m.TestID, "err", err)
					}
				})
				if err := writeJSON(res); err != nil {
					cfg.Logger.Warn("send network test result failed", "test_id", m.TestID, "err", err)
				}
			}(msg)
			continue
		case "upgrade_agent":
			if !updating.CompareAndSwap(false, true) {
				_ = writeJSON(AgentUpdateResultMessage{
					Type:            "agent_update_result",
					UpdateRequestID: msg.UpdateRequestID,
					Success:         false,
					Error:           "another update task is running",
					FromVersion:     cfg.CurrentVersion,
					ToVersion:       strings.TrimSpace(msg.TargetVersion),
					StartedAtMs:     time.Now().UnixMilli(),
					FinishedAtMs:    time.Now().UnixMilli(),
				})
				continue
			}
			go func(m ControlMessage) {
				defer updating.Store(false)
				handleUpgradeAgent(ctx, cfg, m, writeJSON)
			}(msg)
			continue
		case "start_network_rate_stream":
			rateStreamer.Start(func(snap netrate.Snapshot) {
				wrapped := map[string]any{
					"type":         "network_rate",
					"timestamp_ms": snap.TimestampMs,
					"rates":        snap.Rates,
				}
				if err := writeJSON(wrapped); err != nil {
					cfg.Logger.Warn("send network rate failed", "err", err)
				}
			})
			continue
		case "stop_network_rate_stream":
			rateStreamer.Stop()
			continue
		default:
			continue
		}

		// Acquire session slot.
		select {
		case sem <- struct{}{}:
		default:
			cfg.Logger.Warn("max terminal sessions reached, ignoring request", "session_id", msg.SessionID)
			continue
		}

		go func(m ControlMessage) {
			defer func() { <-sem }()

			termURL := strings.TrimSpace(m.TerminalWSURL)
			if termURL == "" {
				termURL = cfg.TerminalWSURL
			}
			sessCfg := SessionConfig{
				Logger:                cfg.Logger.With("component", "terminal"),
				TerminalWSBaseURL:     termURL,
				SessionID:             m.SessionID,
				BearerToken:           m.AgentSessionToken,
				Shell:                 cfg.Shell,
				ShellArgs:             cfg.ShellArgs,
				Term:                  cfg.Term,
				Cols:                  m.Cols,
				Rows:                  m.Rows,
				DialTimeout:           cfg.DialTimeout,
				PingInterval:          cfg.PingInterval,
				TLSInsecureSkipVerify: cfg.TLSInsecureSkipVerify,
				MaxDuration:           cfg.MaxDuration,
				IdleTimeout:           cfg.IdleTimeout,
			}
			cfg.Logger.Info("starting terminal session", "session_id", m.SessionID)
			if err := RunSession(ctx, sessCfg); err != nil {
				cfg.Logger.Warn("terminal session failed", "session_id", m.SessionID, "err", err)
			} else {
				cfg.Logger.Info("terminal session closed", "session_id", m.SessionID)
			}
		}(msg)
	}
}

func handleUpgradeAgent(
	ctx context.Context,
	cfg AgentConfig,
	msg ControlMessage,
	writeJSON func(v any) error,
) {
	startedAt := time.Now()
	targetVersion := strings.TrimSpace(msg.TargetVersion)
	updateRepo := strings.TrimSpace(msg.ReleaseRepo)
	if updateRepo == "" {
		updateRepo = strings.TrimSpace(cfg.UpdateRepo)
	}
	ghProxy := strings.TrimSpace(msg.GitHubProxy)
	if ghProxy == "" {
		ghProxy = strings.TrimSpace(cfg.UpdateGitHubProxy)
	}

	res, err := selfupdate.Apply(ctx, selfupdate.Config{
		Logger:         cfg.Logger.With("component", "self-update"),
		CurrentVersion: cfg.CurrentVersion,
		TargetVersion:  targetVersion,
		Repo:           updateRepo,
		GitHubProxy:    ghProxy,
	})

	out := AgentUpdateResultMessage{
		Type:            "agent_update_result",
		UpdateRequestID: msg.UpdateRequestID,
		Success:         err == nil || errors.Is(err, selfupdate.ErrAlreadyLatest),
		FromVersion:     res.FromVersion,
		ToVersion:       res.ToVersion,
		AssetName:       res.AssetName,
		AssetURL:        res.AssetURL,
		StartedAtMs:     startedAt.UnixMilli(),
		FinishedAtMs:    time.Now().UnixMilli(),
	}
	if err != nil && !errors.Is(err, selfupdate.ErrAlreadyLatest) {
		out.Success = false
		out.Error = err.Error()
		cfg.Logger.Warn("self update failed", "err", err, "request_id", msg.UpdateRequestID)
	} else {
		cfg.Logger.Info("self update completed", "from", out.FromVersion, "to", out.ToVersion, "request_id", msg.UpdateRequestID)
	}
	if err := writeJSON(out); err != nil {
		cfg.Logger.Warn("send update result failed", "err", err, "request_id", msg.UpdateRequestID)
		return
	}

	if out.Success && !errors.Is(err, selfupdate.ErrAlreadyLatest) {
		if rerr := restartSelf(); rerr != nil {
			cfg.Logger.Warn("restart after self update failed", "err", rerr)
		}
	}
}

func restartSelf() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	if p, err := filepath.EvalSymlinks(exePath); err == nil && strings.TrimSpace(p) != "" {
		exePath = p
	}

	// When managed by systemd, exit and let Restart=always recover.
	if os.Getenv("INVOCATION_ID") != "" || os.Getenv("NOTIFY_SOCKET") != "" {
		go func() {
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
		return nil
	}

	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn new process: %w", err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}
