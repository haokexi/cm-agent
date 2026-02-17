package terminal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var iperfIntervalLineRE = regexp.MustCompile(`^\[\s*(SUM|\d+)\]\s+([0-9]+(?:\.[0-9]+)?)\s*-\s*([0-9]+(?:\.[0-9]+)?)\s+sec\s+([0-9]+(?:\.[0-9]+)?)\s+([KMGTP]?Bytes)\s+([0-9]+(?:\.[0-9]+)?)\s+([KMGTP]?bits/sec)(?:\s+([0-9]+))?(?:\s+(sender|receiver))?.*$`)

type iperfParsedLine struct {
	StreamID      string
	IntervalStart float64
	IntervalEnd   float64
	Bytes         int64
	BitsPerSecond float64
	Retransmits   int64
	IsSummary     bool
	SummaryRole   string // sender | receiver
}

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
		return runIperfServer(ctx, res)
	case "client":
		return runIperfClient(ctx, res, emit)
	default:
		res.Error = "invalid role"
		return res
	}
}

func runIperfServer(ctx context.Context, res NetworkTestResultMessage) NetworkTestResultMessage {
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-1", "-p", fmt.Sprintf("%d", res.Port))
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Error = buildCommandError(err, out)
		return res
	}
	res.Success = true
	return res
}

func runIperfClient(
	ctx context.Context,
	res NetworkTestResultMessage,
	emit func(NetworkTestProgressMessage),
) NetworkTestResultMessage {
	if strings.TrimSpace(res.TargetHost) == "" {
		res.Error = "target_host is required for client role"
		return res
	}

	args := []string{
		"-c", strings.TrimSpace(res.TargetHost),
		"-p", fmt.Sprintf("%d", res.Port),
		"-t", fmt.Sprintf("%d", res.DurationSeconds),
		"-P", fmt.Sprintf("%d", res.Parallel),
		"-i", "1",
	}
	cmd := exec.CommandContext(ctx, "iperf3", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		res.Error = "open stdout pipe failed: " + err.Error()
		return res
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		res.Error = "open stderr pipe failed: " + err.Error()
		return res
	}
	if err := cmd.Start(); err != nil {
		res.Error = "start iperf3 failed: " + err.Error()
		return res
	}

	linesCh := make(chan string, 128)
	var scanWG sync.WaitGroup
	scanWG.Add(2)
	go scanIperfLines(stdout, linesCh, &scanWG)
	go scanIperfLines(stderr, linesCh, &scanWG)
	go func() {
		scanWG.Wait()
		close(linesCh)
	}()

	var tail []string
	appendTail := func(line string) {
		if strings.TrimSpace(line) == "" {
			return
		}
		if len(tail) >= 120 {
			tail = tail[1:]
		}
		tail = append(tail, line)
	}

	var lastInterval *iperfParsedLine
	var senderSummary *iperfParsedLine
	var receiverSummary *iperfParsedLine
	var summaryLine string

	for line := range linesCh {
		appendTail(line)
		parsed, ok := parseIperfIntervalLine(line)
		if !ok {
			continue
		}
		// For multi-stream tests, emit only SUM lines to avoid noisy duplicates.
		if res.Parallel > 1 && strings.ToUpper(parsed.StreamID) != "SUM" {
			continue
		}

		if parsed.IsSummary {
			cp := parsed
			switch strings.ToLower(parsed.SummaryRole) {
			case "sender":
				senderSummary = &cp
				summaryLine = line
			case "receiver":
				receiverSummary = &cp
				if summaryLine == "" {
					summaryLine = line
				}
			default:
				if summaryLine == "" {
					summaryLine = line
				}
			}
		} else {
			cp := parsed
			lastInterval = &cp
		}

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
				IntervalStartSec: parsed.IntervalStart,
				IntervalEndSec:   parsed.IntervalEnd,
				BitsPerSecond:    parsed.BitsPerSecond,
				Bytes:            parsed.Bytes,
				Retransmits:      parsed.Retransmits,
				IsSummary:        parsed.IsSummary,
				RawLine:          line,
				TimestampMs:      time.Now().UnixMilli(),
			})
		}
	}

	if err := cmd.Wait(); err != nil {
		res.Error = buildCommandError(err, []byte(strings.Join(tail, "\n")))
		return res
	}

	switch {
	case senderSummary != nil:
		res.BitsPerSecond = senderSummary.BitsPerSecond
		res.Bytes = senderSummary.Bytes
		res.Retransmits = senderSummary.Retransmits
	case receiverSummary != nil:
		res.BitsPerSecond = receiverSummary.BitsPerSecond
		res.Bytes = receiverSummary.Bytes
		res.Retransmits = receiverSummary.Retransmits
	case lastInterval != nil:
		res.BitsPerSecond = lastInterval.BitsPerSecond
		res.Bytes = lastInterval.Bytes
		res.Retransmits = lastInterval.Retransmits
	}
	res.SummaryLine = summaryLine
	res.Success = true
	return res
}

func scanIperfLines(r io.Reader, out chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out <- line
	}
	if err := sc.Err(); err != nil {
		out <- "scan iperf output failed: " + err.Error()
	}
}

func parseIperfIntervalLine(line string) (iperfParsedLine, bool) {
	m := iperfIntervalLineRE.FindStringSubmatch(strings.TrimSpace(line))
	if len(m) != 10 {
		return iperfParsedLine{}, false
	}

	start, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return iperfParsedLine{}, false
	}
	end, err := strconv.ParseFloat(m[3], 64)
	if err != nil {
		return iperfParsedLine{}, false
	}
	transfer, err := strconv.ParseFloat(m[4], 64)
	if err != nil {
		return iperfParsedLine{}, false
	}
	bitrate, err := strconv.ParseFloat(m[6], 64)
	if err != nil {
		return iperfParsedLine{}, false
	}

	var retransmits int64
	if strings.TrimSpace(m[8]) != "" {
		r, err := strconv.ParseInt(m[8], 10, 64)
		if err == nil {
			retransmits = r
		}
	}

	duration := end - start
	summaryRole := strings.ToLower(strings.TrimSpace(m[9]))
	isSummary := summaryRole != "" || duration > 1.5

	return iperfParsedLine{
		StreamID:      strings.ToUpper(strings.TrimSpace(m[1])),
		IntervalStart: start,
		IntervalEnd:   end,
		Bytes:         int64(transfer * byteUnitScale(m[5])),
		BitsPerSecond: bitrate * bitUnitScale(m[7]),
		Retransmits:   retransmits,
		IsSummary:     isSummary,
		SummaryRole:   summaryRole,
	}, true
}

func byteUnitScale(unit string) float64 {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "bytes":
		return 1
	case "kbytes":
		return 1e3
	case "mbytes":
		return 1e6
	case "gbytes":
		return 1e9
	case "tbytes":
		return 1e12
	default:
		return 1
	}
}

func bitUnitScale(unit string) float64 {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "bits/sec":
		return 1
	case "kbits/sec":
		return 1e3
	case "mbits/sec":
		return 1e6
	case "gbits/sec":
		return 1e9
	case "tbits/sec":
		return 1e12
	default:
		return 1
	}
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
