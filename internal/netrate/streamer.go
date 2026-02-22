package netrate

import (
	"bufio"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DeviceRate holds per-device network rate for one sampling interval.
type DeviceRate struct {
	Device string  `json:"device"`
	RxBps  float64 `json:"rx_bps"` // receive bytes per second
	TxBps  float64 `json:"tx_bps"` // transmit bytes per second
}

// Snapshot holds a point-in-time collection of all device rates.
type Snapshot struct {
	TimestampMs int64        `json:"timestamp_ms"`
	Rates       []DeviceRate `json:"rates"`
}

// EmitFunc is called with each computed snapshot.
type EmitFunc func(Snapshot)

// devCounters stores raw counters from /proc/net/dev for one device.
type devCounters struct {
	rxBytes uint64
	txBytes uint64
}

var virtualDeviceRE = regexp.MustCompile(
	`^(lo|docker\d*|veth[a-f0-9]+|br-[a-f0-9]+|virbr\d+|cni\d+|flannel\.\d+|cali[a-f0-9]+|tunl\d+|kube-.*|dummy\d*)$`,
)

// Streamer reads /proc/net/dev at 1-second intervals and emits computed rates.
type Streamer struct {
	logger *slog.Logger
	mu     sync.Mutex
	stopCh chan struct{}
	active bool
}

func New(logger *slog.Logger) *Streamer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Streamer{logger: logger}
}

// Start begins streaming. Idempotent: calling Start on an already-active streamer is a no-op.
func (s *Streamer) Start(emit EmitFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return
	}
	s.active = true
	s.stopCh = make(chan struct{})
	go s.run(s.stopCh, emit)
	s.logger.Info("network rate stream started")
}

// Stop stops streaming. Idempotent.
func (s *Streamer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return
	}
	close(s.stopCh)
	s.active = false
	s.logger.Info("network rate stream stopped")
}

func (s *Streamer) run(stopCh <-chan struct{}, emit EmitFunc) {
	prev := readNetDev()
	prevTime := time.Now()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			cur := readNetDev()
			dt := now.Sub(prevTime).Seconds()
			if dt <= 0 {
				dt = 1
			}

			var rates []DeviceRate
			for dev, cc := range cur {
				if virtualDeviceRE.MatchString(dev) {
					continue
				}
				pc, ok := prev[dev]
				if !ok {
					continue
				}
				var rxDelta, txDelta uint64
				if cc.rxBytes >= pc.rxBytes {
					rxDelta = cc.rxBytes - pc.rxBytes
				}
				if cc.txBytes >= pc.txBytes {
					txDelta = cc.txBytes - pc.txBytes
				}
				rates = append(rates, DeviceRate{
					Device: dev,
					RxBps:  float64(rxDelta) / dt,
					TxBps:  float64(txDelta) / dt,
				})
			}

			if len(rates) > 0 {
				emit(Snapshot{
					TimestampMs: now.UnixMilli(),
					Rates:       rates,
				})
			}

			prev = cur
			prevTime = now
		}
	}
}

// readNetDev parses /proc/net/dev and returns counters by device name.
func readNetDev() map[string]devCounters {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()

	result := make(map[string]devCounters)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "|") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		dev := strings.TrimSpace(parts[0])
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 10 {
			continue
		}
		rxBytes, err1 := strconv.ParseUint(fields[0], 10, 64)
		txBytes, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		result[dev] = devCounters{rxBytes: rxBytes, txBytes: txBytes}
	}
	return result
}
