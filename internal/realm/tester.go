package realm

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type RuleTestRequest struct {
	RequestID string
	Listen    string
	Remote    string
}

type RuleTestResult struct {
	RequestID string `json:"request_id,omitempty"`

	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`

	ListenAddress    string `json:"listen_address,omitempty"`
	RemoteAddress    string `json:"remote_address,omitempty"`
	ListenReachable  bool   `json:"listen_reachable"`
	RemoteReachable  bool   `json:"remote_reachable"`
	ListenTestTarget string `json:"listen_test_target,omitempty"`
	ListenError      string `json:"listen_error,omitempty"`
	RemoteError      string `json:"remote_error,omitempty"`

	StartedAtMs  int64 `json:"started_at_ms,omitempty"`
	FinishedAtMs int64 `json:"finished_at_ms,omitempty"`
}

func TestRule(ctx context.Context, req RuleTestRequest) RuleTestResult {
	startedAt := time.Now()
	out := RuleTestResult{
		RequestID:     strings.TrimSpace(req.RequestID),
		ListenAddress: strings.TrimSpace(req.Listen),
		RemoteAddress: strings.TrimSpace(req.Remote),
		StartedAtMs:   startedAt.UnixMilli(),
	}
	defer func() {
		out.FinishedAtMs = time.Now().UnixMilli()
	}()

	if strings.TrimSpace(req.Listen) == "" {
		out.Error = "listen address is required"
		return out
	}
	if strings.TrimSpace(req.Remote) == "" {
		out.Error = "remote address is required"
		return out
	}

	listenTarget, listenErr := testListenCandidates(ctx, req.Listen)
	out.ListenTestTarget = listenTarget
	if listenErr != nil {
		out.ListenError = listenErr.Error()
	} else {
		out.ListenReachable = true
	}

	if err := testTCPDial(ctx, req.Remote); err != nil {
		out.RemoteError = err.Error()
	} else {
		out.RemoteReachable = true
	}

	out.Success = out.ListenReachable && out.RemoteReachable
	switch {
	case out.Success:
		out.Message = "listen and remote are reachable"
	case out.ListenReachable && !out.RemoteReachable:
		out.Message = "listen is reachable but remote is unreachable"
	case !out.ListenReachable && out.RemoteReachable:
		out.Message = "remote is reachable but listen is unreachable"
	default:
		out.Message = "listen and remote are unreachable"
	}
	return out
}

func testListenCandidates(ctx context.Context, listen string) (string, error) {
	candidates, err := buildListenCandidates(listen)
	if err != nil {
		return "", err
	}

	var errs []string
	for _, candidate := range candidates {
		if err := testTCPDial(ctx, candidate); err == nil {
			return candidate, nil
		} else {
			errs = append(errs, fmt.Sprintf("%s (%s)", candidate, err.Error()))
		}
	}
	return firstNonEmpty(candidates...), fmt.Errorf("%s", strings.Join(errs, "; "))
}

func buildListenCandidates(listen string) ([]string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("invalid port %q", port)
	}

	switch host {
	case "0.0.0.0":
		return []string{net.JoinHostPort("127.0.0.1", port)}, nil
	case "::":
		return []string{
			net.JoinHostPort("::1", port),
			net.JoinHostPort("127.0.0.1", port),
		}, nil
	default:
		return []string{net.JoinHostPort(host, port)}, nil
	}
}

func testTCPDial(ctx context.Context, address string) error {
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", strings.TrimSpace(address))
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
