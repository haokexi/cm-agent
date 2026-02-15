package terminal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

type SessionConfig struct {
	Logger *slog.Logger

	TerminalWSBaseURL string // e.g. wss://server/api/agent/terminal/ws
	SessionID         string
	BearerToken       string // one-time token

	Shell     string
	ShellArgs []string
	// Term is exported to the PTY process as TERM. This is required for interactive
	// TUIs like top/htop/vim to render correctly. systemd services often have TERM unset.
	Term string

	Cols int
	Rows int

	DialTimeout           time.Duration
	PingInterval          time.Duration
	TLSInsecureSkipVerify bool

	MaxDuration time.Duration
	IdleTimeout time.Duration
}

func RunSession(ctx context.Context, cfg SessionConfig) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/bash"
	}
	if len(cfg.ShellArgs) == 0 {
		cfg.ShellArgs = []string{"-l"}
	}
	if strings.TrimSpace(cfg.Term) == "" {
		cfg.Term = "xterm-256color"
	}
	if cfg.SessionID == "" {
		return errors.New("session id is required")
	}
	if strings.TrimSpace(cfg.TerminalWSBaseURL) == "" {
		return errors.New("terminal ws base url is required")
	}
	if strings.TrimSpace(cfg.BearerToken) == "" {
		return errors.New("session bearer token is required")
	}

	// Build ws URL with session_id query param.
	wsURL, err := withQuery(cfg.TerminalWSBaseURL, "session_id", cfg.SessionID)
	if err != nil {
		return err
	}

	sctx := ctx
	if cfg.MaxDuration > 0 {
		var cancel context.CancelFunc
		sctx, cancel = context.WithTimeout(ctx, cfg.MaxDuration)
		defer cancel()
	}

	// Start PTY shell.
	cmd := exec.CommandContext(sctx, cfg.Shell, cfg.ShellArgs...)
	cmd.Env = upsertEnv(os.Environ(), "TERM", cfg.Term)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	if cfg.Cols > 0 && cfg.Rows > 0 {
		_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cfg.Cols), Rows: uint16(cfg.Rows)})
	}

	// Dial terminal WS.
	dialer := websocket.Dialer{
		HandshakeTimeout: cfg.DialTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify, //nolint:gosec
		},
	}
	hdr := map[string][]string{
		"Authorization": {"Bearer " + strings.TrimSpace(cfg.BearerToken)},
	}
	ws, _, err := dialer.DialContext(sctx, wsURL, hdr)
	if err != nil {
		return fmt.Errorf("dial terminal ws: %w", err)
	}
	defer ws.Close()

	ws.SetReadLimit(4 << 20) // 4MiB per message cap

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	touch := func() { lastActivity.Store(time.Now().UnixNano()) }

	errCh := make(chan error, 2)

	// PTY -> WS
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			touch()
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// WS -> PTY (binary), resize control (text/json)
	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			touch()
			switch mt {
			case websocket.BinaryMessage:
				if _, err := ptmx.Write(data); err != nil {
					errCh <- err
					return
				}
			case websocket.TextMessage:
				var rm ResizeMessage
				if err := json.Unmarshal(data, &rm); err == nil && rm.Type == "resize" {
					if rm.Cols > 0 && rm.Rows > 0 && rm.Cols < 10000 && rm.Rows < 10000 {
						_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(rm.Cols), Rows: uint16(rm.Rows)})
					}
				}
				// ignore other control frames in MVP
			}
		}
	}()

	// Ping loop (keepalive).
	go func() {
		t := time.NewTicker(cfg.PingInterval)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				_ = ws.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
			}
		}
	}()

	// Idle timeout watcher.
	if cfg.IdleTimeout > 0 {
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-sctx.Done():
					return
				case <-t.C:
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) > cfg.IdleTimeout {
						errCh <- fmt.Errorf("idle timeout: %s", cfg.IdleTimeout)
						return
					}
				}
			}
		}()
	}

	select {
	case <-sctx.Done():
		return sctx.Err()
	case err := <-errCh:
		if errors.Is(err, io.EOF) {
			return nil
		}
		// websocket normal closure is fine.
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			return nil
		}
		cfg.Logger.Info("terminal session ended", "session_id", cfg.SessionID, "err", err)
		return err
	}
}

func withQuery(base, k, v string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func upsertEnv(env []string, k, v string) []string {
	k = strings.TrimSpace(k)
	if k == "" {
		return env
	}
	prefix := k + "="
	for i := range env {
		if strings.HasPrefix(env[i], prefix) {
			env[i] = prefix + v
			return env
		}
	}
	return append(env, prefix+v)
}
