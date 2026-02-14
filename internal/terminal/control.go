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
	"strings"
	"sync"
	"time"

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

	MaxSessions int
	MaxDuration time.Duration
	IdleTimeout time.Duration
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

	// keepalive ping
	pingCtx, pingCancel := context.WithCancel(ctx)
	defer pingCancel()

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
				_ = ws.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
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
		if msg.Type != "open_terminal" {
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
