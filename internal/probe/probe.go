package probe

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Config struct {
	Logger  *slog.Logger
	Timeout time.Duration
	ICMP    []string
	TCP     []string
	Targets []Target
}

type Target struct {
	Module         string
	Instance       string
	IPProtocol     string
	RuleID         string
	Timeout        time.Duration
	Count          int
	PacketInterval time.Duration
}

type PingResult struct {
	Sent     int
	Received int
	Loss     float64
	MinRTT   time.Duration
	MaxRTT   time.Duration
	AvgRTT   time.Duration
	StdDev   time.Duration
}

type Collector struct {
	cfg Config

	descSuccess  *prometheus.Desc
	descDuration *prometheus.Desc

	descICMPRTT       *prometheus.Desc
	descICMPRTTMin    *prometheus.Desc
	descICMPRTTMax    *prometheus.Desc
	descICMPRTTStdDev *prometheus.Desc
	descICMPLoss      *prometheus.Desc
	descICMPSent      *prometheus.Desc
	descICMPRecv      *prometheus.Desc

	descTCPConn *prometheus.Desc
}

func NewCollector(cfg Config) *Collector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	labels := []string{"module", "instance", "probe_rule_id"}
	return &Collector{
		cfg: cfg,
		descSuccess: prometheus.NewDesc(
			"probe_success",
			"Displays whether or not the probe was a success.",
			labels, nil,
		),
		descDuration: prometheus.NewDesc(
			"probe_duration_seconds",
			"Returns how long the probe took to complete in seconds.",
			labels, nil,
		),
		descICMPRTT: prometheus.NewDesc(
			"probe_icmp_rtt_seconds",
			"Average round trip time for ICMP ping, in seconds.",
			labels, nil,
		),
		descICMPRTTMin: prometheus.NewDesc(
			"probe_icmp_rtt_min_seconds",
			"Minimum round trip time for ICMP ping, in seconds.",
			labels, nil,
		),
		descICMPRTTMax: prometheus.NewDesc(
			"probe_icmp_rtt_max_seconds",
			"Maximum round trip time for ICMP ping, in seconds.",
			labels, nil,
		),
		descICMPRTTStdDev: prometheus.NewDesc(
			"probe_icmp_rtt_stddev_seconds",
			"Standard deviation of ICMP RTT (jitter), in seconds.",
			labels, nil,
		),
		descICMPLoss: prometheus.NewDesc(
			"probe_icmp_packet_loss_ratio",
			"ICMP packet loss ratio (0.0 to 1.0).",
			labels, nil,
		),
		descICMPSent: prometheus.NewDesc(
			"probe_icmp_packets_sent",
			"Number of ICMP echo requests sent.",
			labels, nil,
		),
		descICMPRecv: prometheus.NewDesc(
			"probe_icmp_packets_received",
			"Number of ICMP echo replies received.",
			labels, nil,
		),
		descTCPConn: prometheus.NewDesc(
			"probe_tcp_connect_duration_seconds",
			"Duration of TCP connection establishment, in seconds.",
			labels, nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descSuccess
	ch <- c.descDuration
	ch <- c.descICMPRTT
	ch <- c.descICMPRTTMin
	ch <- c.descICMPRTTMax
	ch <- c.descICMPRTTStdDev
	ch <- c.descICMPLoss
	ch <- c.descICMPSent
	ch <- c.descICMPRecv
	ch <- c.descTCPConn
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	logger := c.cfg.Logger
	targets := c.buildTargets()

	for _, item := range targets {
		module := strings.TrimSpace(item.Module)
		tgt := strings.TrimSpace(item.Instance)
		if module == "" || tgt == "" {
			continue
		}
		ruleID := strings.TrimSpace(item.RuleID)
		if ruleID == "" {
			ruleID = "0"
		}
		timeout := item.Timeout
		if timeout <= 0 {
			timeout = c.cfg.Timeout
		}
		start := time.Now()
		switch module {
		case "icmp":
			count := item.Count
			if count <= 0 {
				count = 5
			}
			interval := item.PacketInterval
			if interval <= 0 {
				interval = 200 * time.Millisecond
			}
			result, err := pingN(tgt, timeout, item.IPProtocol, count, interval)
			d := time.Since(start)
			lv := []string{module, tgt, ruleID}
			if err != nil {
				logger.Debug("probe failed", "module", module, "target", tgt, "rule_id", ruleID, "err", err)
				ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 0, lv...)
				ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), lv...)
				ch <- prometheus.MustNewConstMetric(c.descICMPLoss, prometheus.GaugeValue, 1, lv...)
				ch <- prometheus.MustNewConstMetric(c.descICMPSent, prometheus.GaugeValue, float64(count), lv...)
				ch <- prometheus.MustNewConstMetric(c.descICMPRecv, prometheus.GaugeValue, 0, lv...)
				continue
			}
			success := 0.0
			if result.Received > 0 {
				success = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, success, lv...)
			ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPLoss, prometheus.GaugeValue, result.Loss, lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPSent, prometheus.GaugeValue, float64(result.Sent), lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPRecv, prometheus.GaugeValue, float64(result.Received), lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPRTT, prometheus.GaugeValue, result.AvgRTT.Seconds(), lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPRTTMin, prometheus.GaugeValue, result.MinRTT.Seconds(), lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPRTTMax, prometheus.GaugeValue, result.MaxRTT.Seconds(), lv...)
			ch <- prometheus.MustNewConstMetric(c.descICMPRTTStdDev, prometheus.GaugeValue, result.StdDev.Seconds(), lv...)
		case "tcp_connect":
			cd, err := tcpConnectOnce(tgt, timeout)
			d := time.Since(start)
			if err != nil {
				logger.Debug("probe failed", "module", module, "target", tgt, "rule_id", ruleID, "err", err)
				ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 0, module, tgt, ruleID)
				ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt, ruleID)
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 1, module, tgt, ruleID)
			ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt, ruleID)
			ch <- prometheus.MustNewConstMetric(c.descTCPConn, prometheus.GaugeValue, cd.Seconds(), module, tgt, ruleID)
		default:
			continue
		}
	}
}

func (c *Collector) buildTargets() []Target {
	var out []Target
	if len(c.cfg.Targets) > 0 {
		out = append(out, c.cfg.Targets...)
	}
	for _, tgt := range c.cfg.ICMP {
		t := strings.TrimSpace(tgt)
		if t == "" {
			continue
		}
		out = append(out, Target{
			Module:     "icmp",
			Instance:   t,
			IPProtocol: "auto",
			RuleID:     "0",
			Timeout:    c.cfg.Timeout,
		})
	}
	for _, tgt := range c.cfg.TCP {
		t := strings.TrimSpace(tgt)
		if t == "" {
			continue
		}
		out = append(out, Target{
			Module:   "tcp_connect",
			Instance: t,
			RuleID:   "0",
			Timeout:  c.cfg.Timeout,
		})
	}
	return out
}

func tcpConnectOnce(target string, timeout time.Duration) (time.Duration, error) {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return 0, fmt.Errorf("invalid tcp target %q (expected host:port): %w", target, err)
	}
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.Dial("tcp", target)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// pingN sends count ICMP echo requests to target and collects replies.
func pingN(target string, timeout time.Duration, ipProtocol string, count int, interval time.Duration) (*PingResult, error) {
	switch normalizeIPProtocol(ipProtocol) {
	case "ipv4":
		ipaddr, err := net.ResolveIPAddr("ip4", target)
		if err != nil {
			return nil, err
		}
		if ipaddr.IP == nil {
			return nil, errors.New("no ipv4 resolved")
		}
		return pingNIPv4(ipaddr, timeout, count, interval)
	case "ipv6":
		ipaddr, err := net.ResolveIPAddr("ip6", target)
		if err != nil {
			return nil, err
		}
		if ipaddr.IP == nil {
			return nil, errors.New("no ipv6 resolved")
		}
		return pingNIPv6(ipaddr, timeout, count, interval)
	default:
		ipaddr, err := net.ResolveIPAddr("ip", target)
		if err != nil {
			return nil, err
		}
		if ipaddr.IP == nil {
			return nil, errors.New("no ip resolved")
		}
		if ipaddr.IP.To4() != nil {
			return pingNIPv4(ipaddr, timeout, count, interval)
		}
		return pingNIPv6(ipaddr, timeout, count, interval)
	}
}

func pingNIPv4(dst *net.IPAddr, timeout time.Duration, count int, interval time.Duration) (*PingResult, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	id := int(uint32(time.Now().UnixNano()) & 0xffff)
	sendTimes := make([]time.Time, count)

	var wg sync.WaitGroup
	rtts := make([]time.Duration, count)
	received := make([]bool, count)

	// Sender goroutine
	wg.Add(1)
	var lastSendTime time.Time
	var sendErr error
	go func() {
		defer wg.Done()
		for seq := 0; seq < count; seq++ {
			if seq > 0 {
				time.Sleep(interval)
			}
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cm-agent")},
			}
			b, err := msg.Marshal(nil)
			if err != nil {
				sendErr = err
				return
			}
			sendTimes[seq] = time.Now()
			if _, err := c.WriteTo(b, dst); err != nil {
				sendErr = err
				return
			}
		}
		lastSendTime = time.Now()
	}()

	// Receiver goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		rb := make([]byte, 1500)
		got := 0
		for got < count {
			deadline := time.Now().Add(timeout)
			if !lastSendTime.IsZero() {
				dl := lastSendTime.Add(timeout)
				if dl.Before(deadline) {
					deadline = dl
				}
			}
			_ = c.SetDeadline(deadline)

			n, _, err := c.ReadFrom(rb)
			if err != nil {
				return
			}
			rm, err := icmp.ParseMessage(1, rb[:n])
			if err != nil {
				continue
			}
			if rm.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			body, ok := rm.Body.(*icmp.Echo)
			if !ok || body.ID != id {
				continue
			}
			seq := body.Seq
			if seq < 0 || seq >= count || received[seq] {
				continue
			}
			received[seq] = true
			rtts[seq] = time.Since(sendTimes[seq])
			got++
		}
	}()

	wg.Wait()
	if sendErr != nil {
		return nil, fmt.Errorf("ping send: %w", sendErr)
	}
	return computePingResult(count, received, rtts), nil
}

func pingNIPv6(dst *net.IPAddr, timeout time.Duration, count int, interval time.Duration) (*PingResult, error) {
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	id := int(uint32(time.Now().UnixNano()) & 0xffff)
	sendTimes := make([]time.Time, count)

	var wg sync.WaitGroup
	rtts := make([]time.Duration, count)
	received := make([]bool, count)

	wg.Add(1)
	var lastSendTime time.Time
	var sendErr error
	go func() {
		defer wg.Done()
		for seq := 0; seq < count; seq++ {
			if seq > 0 {
				time.Sleep(interval)
			}
			msg := icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest,
				Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cm-agent")},
			}
			b, err := msg.Marshal(nil)
			if err != nil {
				sendErr = err
				return
			}
			sendTimes[seq] = time.Now()
			if _, err := c.WriteTo(b, dst); err != nil {
				sendErr = err
				return
			}
		}
		lastSendTime = time.Now()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		rb := make([]byte, 1500)
		got := 0
		for got < count {
			deadline := time.Now().Add(timeout)
			if !lastSendTime.IsZero() {
				dl := lastSendTime.Add(timeout)
				if dl.Before(deadline) {
					deadline = dl
				}
			}
			_ = c.SetDeadline(deadline)

			n, _, err := c.ReadFrom(rb)
			if err != nil {
				return
			}
			rm, err := icmp.ParseMessage(58, rb[:n])
			if err != nil {
				continue
			}
			if rm.Type != ipv6.ICMPTypeEchoReply {
				continue
			}
			body, ok := rm.Body.(*icmp.Echo)
			if !ok || body.ID != id {
				continue
			}
			seq := body.Seq
			if seq < 0 || seq >= count || received[seq] {
				continue
			}
			received[seq] = true
			rtts[seq] = time.Since(sendTimes[seq])
			got++
		}
	}()

	wg.Wait()
	if sendErr != nil {
		return nil, fmt.Errorf("ping send: %w", sendErr)
	}
	return computePingResult(count, received, rtts), nil
}

func computePingResult(count int, received []bool, rtts []time.Duration) *PingResult {
	r := &PingResult{Sent: count}
	var sum float64
	var vals []float64
	minRTT := time.Duration(math.MaxInt64)
	var maxRTT time.Duration

	for i := 0; i < count; i++ {
		if !received[i] {
			continue
		}
		r.Received++
		d := rtts[i]
		sec := d.Seconds()
		vals = append(vals, sec)
		sum += sec
		if d < minRTT {
			minRTT = d
		}
		if d > maxRTT {
			maxRTT = d
		}
	}

	if r.Received == 0 {
		r.Loss = 1.0
		return r
	}

	r.Loss = float64(r.Sent-r.Received) / float64(r.Sent)
	avg := sum / float64(r.Received)
	r.AvgRTT = time.Duration(avg * float64(time.Second))
	r.MinRTT = minRTT
	r.MaxRTT = maxRTT

	var variance float64
	for _, v := range vals {
		diff := v - avg
		variance += diff * diff
	}
	variance /= float64(r.Received)
	r.StdDev = time.Duration(math.Sqrt(variance) * float64(time.Second))

	return r
}

func normalizeIPProtocol(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ipv4", "ip4":
		return "ipv4"
	case "ipv6", "ip6":
		return "ipv6"
	default:
		return "auto"
	}
}
