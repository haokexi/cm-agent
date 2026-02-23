package terminal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cm-agent/internal/speedtest"
)

func runNetworkTestTask(
	parent context.Context,
	cfg AgentConfig,
	msg ControlMessage,
	emit func(NetworkTestProgressMessage),
) NetworkTestResultMessage {
	res := NetworkTestResultMessage{
		Type:            "network_test_result",
		TestID:          strings.TrimSpace(msg.TestID),
		RootTestID:      strings.TrimSpace(msg.RootTestID),
		Direction:       strings.TrimSpace(msg.Direction),
		Role:            strings.TrimSpace(msg.Role),
		Protocol:        nonEmpty(strings.TrimSpace(msg.Protocol), "tcp"),
		TargetHost:      strings.TrimSpace(msg.TargetHost),
		Port:            msg.Port,
		DurationSeconds: msg.DurationSeconds,
		Parallel:        msg.Parallel,
	}

	role := strings.ToLower(strings.TrimSpace(msg.Role))
	if role != "server" && role != "client" {
		res.Error = "invalid role: must be server/client"
		return res
	}
	if res.Port <= 0 {
		res.Port = 5201
	}
	if res.DurationSeconds <= 0 {
		res.DurationSeconds = 10
	}
	if res.Parallel <= 0 {
		res.Parallel = 1
	}

	timeout := time.Duration(res.DurationSeconds+40) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	switch role {
	case "server":
		return runBuiltinServer(ctx, res)
	case "client":
		return runBuiltinClient(ctx, res, msg.Reverse, emit)
	default:
		res.Error = "invalid role"
		return res
	}
}

func runBuiltinServer(ctx context.Context, res NetworkTestResultMessage) NetworkTestResultMessage {
	if err := speedtest.RunServer(ctx, res.Port); err != nil {
		res.Error = "server failed: " + err.Error()
		return res
	}
	res.Success = true
	return res
}

func runBuiltinClient(
	ctx context.Context,
	res NetworkTestResultMessage,
	reverse bool,
	emit func(NetworkTestProgressMessage),
) NetworkTestResultMessage {
	host := strings.TrimSpace(res.TargetHost)
	if host == "" {
		res.Error = "target_host is required for client role"
		return res
	}

	duration := time.Duration(res.DurationSeconds) * time.Second

	var onInterval func(speedtest.IntervalReport)
	if emit != nil {
		onInterval = func(r speedtest.IntervalReport) {
			raw := fmt.Sprintf("  [SUM]  %.1f-%.1f sec  %s  %s",
				r.IntervalStart, r.IntervalEnd,
				fmtBytes(r.Bytes), fmtBitsPerSec(r.BitsPerSec))
			emit(NetworkTestProgressMessage{
				Type:             "network_test_progress",
				TestID:           res.TestID,
				RootTestID:       res.RootTestID,
				Direction:        res.Direction,
				Role:             res.Role,
				Protocol:         res.Protocol,
				TargetHost:       res.TargetHost,
				Port:             res.Port,
				DurationSeconds:  res.DurationSeconds,
				Parallel:         res.Parallel,
				IntervalStartSec: r.IntervalStart,
				IntervalEndSec:   r.IntervalEnd,
				BitsPerSecond:    r.BitsPerSec,
				Bytes:            r.Bytes,
				IsSummary:        false,
				RawLine:          raw,
				TimestampMs:      time.Now().UnixMilli(),
			})
		}
	}

	result := speedtest.RunClient(ctx, host, res.Port, duration, res.Parallel, reverse, onInterval)

	res.Success = result.Success
	res.Error = result.Error
	res.BitsPerSecond = result.BitsPerSec
	res.Bytes = result.TotalBytes

	if result.Success {
		res.SummaryLine = fmt.Sprintf("  [SUM]  0.0-%.1f sec  %s  %s  sender",
			result.Duration.Seconds(),
			fmtBytes(result.TotalBytes), fmtBitsPerSec(result.BitsPerSec))

		// Emit final summary as progress.
		if emit != nil {
			emit(NetworkTestProgressMessage{
				Type:             "network_test_progress",
				TestID:           res.TestID,
				RootTestID:       res.RootTestID,
				Direction:        res.Direction,
				Role:             res.Role,
				Protocol:         res.Protocol,
				TargetHost:       res.TargetHost,
				Port:             res.Port,
				DurationSeconds:  res.DurationSeconds,
				Parallel:         res.Parallel,
				IntervalStartSec: 0,
				IntervalEndSec:   result.Duration.Seconds(),
				BitsPerSecond:    result.BitsPerSec,
				Bytes:            result.TotalBytes,
				IsSummary:        true,
				RawLine:          res.SummaryLine,
				TimestampMs:      time.Now().UnixMilli(),
			})
		}
	}

	return res
}

func fmtBytes(b int64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.1f GBytes", float64(b)/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f MBytes", float64(b)/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0f KBytes", float64(b)/1e3)
	default:
		return fmt.Sprintf("%d Bytes", b)
	}
}

func fmtBitsPerSec(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbits/sec", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mbits/sec", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.0f Kbits/sec", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bits/sec", bps)
	}
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
