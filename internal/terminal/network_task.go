package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func runNetworkTestTask(parent context.Context, cfg AgentConfig, msg ControlMessage) NetworkTestResultMessage {
	res := NetworkTestResultMessage{
		Type:            "network_test_result",
		TestID:          strings.TrimSpace(msg.TestID),
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

	timeout := time.Duration(res.DurationSeconds+20) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	switch role {
	case "server":
		return runIperfServer(ctx, res)
	case "client":
		return runIperfClient(ctx, res)
	default:
		res.Error = "invalid role"
		return res
	}
}

func runIperfServer(ctx context.Context, res NetworkTestResultMessage) NetworkTestResultMessage {
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-1", "-p", fmt.Sprintf("%d", res.Port), "-J")
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Error = buildCommandError(err, out)
		return res
	}
	// Server side output is currently not used by controller orchestration.
	res.Success = true
	return res
}

func runIperfClient(ctx context.Context, res NetworkTestResultMessage) NetworkTestResultMessage {
	if strings.TrimSpace(res.TargetHost) == "" {
		res.Error = "target_host is required for client role"
		return res
	}
	args := []string{
		"-c", strings.TrimSpace(res.TargetHost),
		"-p", fmt.Sprintf("%d", res.Port),
		"-t", fmt.Sprintf("%d", res.DurationSeconds),
		"-P", fmt.Sprintf("%d", res.Parallel),
		"-J",
	}
	cmd := exec.CommandContext(ctx, "iperf3", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Error = buildCommandError(err, out)
		return res
	}
	if err := fillClientResultFromJSON(out, &res); err != nil {
		res.Error = "parse iperf3 json failed: " + err.Error()
		return res
	}
	res.Success = true
	return res
}

func fillClientResultFromJSON(raw []byte, out *NetworkTestResultMessage) error {
	var payload struct {
		Error string `json:"error"`
		End   struct {
			SumSent struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				Bytes         int64   `json:"bytes"`
				Retransmits   int64   `json:"retransmits"`
			} `json:"sum_sent"`
			Sum struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				Bytes         int64   `json:"bytes"`
				JitterMs      float64 `json:"jitter_ms"`
				LostPercent   float64 `json:"lost_percent"`
			} `json:"sum"`
		} `json:"end"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	if strings.TrimSpace(payload.Error) != "" {
		return errors.New(payload.Error)
	}
	// For TCP, sum_sent is the primary throughput view from client side.
	if payload.End.SumSent.BitsPerSecond > 0 {
		out.BitsPerSecond = payload.End.SumSent.BitsPerSecond
		out.Bytes = payload.End.SumSent.Bytes
		out.Retransmits = payload.End.SumSent.Retransmits
		return nil
	}
	// Fallback for unexpected format (e.g., UDP-oriented sum block).
	out.BitsPerSecond = payload.End.Sum.BitsPerSecond
	out.Bytes = payload.End.Sum.Bytes
	out.JitterMs = payload.End.Sum.JitterMs
	out.LostPercent = payload.End.Sum.LostPercent
	return nil
}

func buildCommandError(err error, raw []byte) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(string(raw))
	if msg == "" {
		return err.Error()
	}
	if len(msg) > 400 {
		msg = msg[:400]
	}
	return err.Error() + ": " + msg
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
