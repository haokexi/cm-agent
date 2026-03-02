package probe

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Config struct {
	Logger        *slog.Logger
	Timeout       time.Duration
	ICMPEchoCount int
	ICMP          []string
	TCP           []string
	Targets       []Target
}

type Target struct {
	Module     string
	Instance   string
	IPProtocol string
	RuleID     string
	Timeout    time.Duration
}

// Collector runs "blackbox-like" probes (ICMP ping and TCP connect) and emits results as metrics.
// This agent does not expose /probe; it performs the probes in-process and ships results via remote_write.
type Collector struct {
	cfg Config

	descSuccess  *prometheus.Desc
	descDuration *prometheus.Desc

	descICMPRTT  *prometheus.Desc
	descICMPLoss *prometheus.Desc
	descTCPConn  *prometheus.Desc
}

const (
	defaultICMPEchoCount = 5
	maxICMPEchoCount     = 20
)

func NewCollector(cfg Config) *Collector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	cfg.ICMPEchoCount = normalizeICMPEchoCount(cfg.ICMPEchoCount)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	labels := []string{"module", "instance", "probe_rule_id", "ipv4", "ipv6"}
	return &Collector{
		cfg: cfg,
		descSuccess: prometheus.NewDesc(
			"probe_success",
			"Displays whether or not the probe was a success.",
			labels,
			nil,
		),
		descDuration: prometheus.NewDesc(
			"probe_duration_seconds",
			"Returns how long the probe took to complete in seconds.",
			labels,
			nil,
		),
		descICMPRTT: prometheus.NewDesc(
			"probe_icmp_rtt_seconds",
			"Round trip time for ICMP ping, in seconds.",
			labels,
			nil,
		),
		descICMPLoss: prometheus.NewDesc(
			"probe_icmp_loss_percent",
			"Packet loss percentage for ICMP ping, in percent.",
			labels,
			nil,
		),
		descTCPConn: prometheus.NewDesc(
			"probe_tcp_connect_duration_seconds",
			"Duration of TCP connection establishment, in seconds.",
			labels,
			nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descSuccess
	ch <- c.descDuration
	ch <- c.descICMPRTT
	ch <- c.descICMPLoss
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
		ipv4Label, ipv6Label := resolveProbeIPs(module, tgt)
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
			res, err := pingOnce(tgt, timeout, item.IPProtocol, c.cfg.ICMPEchoCount)
			d := time.Since(start)
			if err != nil {
				logger.Debug("probe failed", "module", module, "target", tgt, "rule_id", ruleID, "err", err)
				ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 0, module, tgt, ruleID, ipv4Label, ipv6Label)
				ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt, ruleID, ipv4Label, ipv6Label)
				if res.Sent > 0 {
					ch <- prometheus.MustNewConstMetric(c.descICMPLoss, prometheus.GaugeValue, res.LossPercent(), module, tgt, ruleID, ipv4Label, ipv6Label)
				}
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 1, module, tgt, ruleID, ipv4Label, ipv6Label)
			ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt, ruleID, ipv4Label, ipv6Label)
			ch <- prometheus.MustNewConstMetric(c.descICMPRTT, prometheus.GaugeValue, res.RTT.Seconds(), module, tgt, ruleID, ipv4Label, ipv6Label)
			ch <- prometheus.MustNewConstMetric(c.descICMPLoss, prometheus.GaugeValue, res.LossPercent(), module, tgt, ruleID, ipv4Label, ipv6Label)
		case "tcp_connect":
			cd, err := tcpConnectOnce(tgt, timeout)
			d := time.Since(start)
			if err != nil {
				logger.Debug("probe failed", "module", module, "target", tgt, "rule_id", ruleID, "err", err)
				ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 0, module, tgt, ruleID, ipv4Label, ipv6Label)
				ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt, ruleID, ipv4Label, ipv6Label)
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 1, module, tgt, ruleID, ipv4Label, ipv6Label)
			ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt, ruleID, ipv4Label, ipv6Label)
			ch <- prometheus.MustNewConstMetric(c.descTCPConn, prometheus.GaugeValue, cd.Seconds(), module, tgt, ruleID, ipv4Label, ipv6Label)
		default:
			continue
		}
	}
}

type pingResult struct {
	RTT      time.Duration
	Sent     int
	Received int
}

func (r pingResult) LossPercent() float64 {
	if r.Sent <= 0 {
		return 0
	}
	lost := r.Sent - r.Received
	if lost < 0 {
		lost = 0
	}
	return float64(lost) * 100 / float64(r.Sent)
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

func pingOnce(target string, timeout time.Duration, ipProtocol string, echoCount int) (pingResult, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	echoCount = normalizeICMPEchoCount(echoCount)
	switch normalizeIPProtocol(ipProtocol) {
	case "ipv4":
		ipaddr, err := net.ResolveIPAddr("ip4", target)
		if err != nil {
			return pingResult{}, err
		}
		if ipaddr.IP == nil {
			return pingResult{}, errors.New("no ipv4 resolved")
		}
		return pingIPv4(ipaddr, timeout, echoCount)
	case "ipv6":
		ipaddr, err := net.ResolveIPAddr("ip6", target)
		if err != nil {
			return pingResult{}, err
		}
		if ipaddr.IP == nil {
			return pingResult{}, errors.New("no ipv6 resolved")
		}
		return pingIPv6(ipaddr, timeout, echoCount)
	default:
		ipaddr, err := net.ResolveIPAddr("ip", target)
		if err != nil {
			return pingResult{}, err
		}
		if ipaddr.IP == nil {
			return pingResult{}, errors.New("no ip resolved")
		}
		if ipaddr.IP.To4() != nil {
			return pingIPv4(ipaddr, timeout, echoCount)
		}
		return pingIPv6(ipaddr, timeout, echoCount)
	}
}

func normalizeICMPEchoCount(v int) int {
	if v <= 0 {
		return defaultICMPEchoCount
	}
	if v > maxICMPEchoCount {
		return maxICMPEchoCount
	}
	return v
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

func resolveProbeIPs(module, instance string) (ipv4Label string, ipv6Label string) {
	host := strings.TrimSpace(instance)
	if host == "" {
		return "", ""
	}
	if strings.TrimSpace(module) == "tcp_connect" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", ""
	}

	// Fast path for IP literals to avoid DNS.
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return addr.String(), ""
		}
		if addr.Is6() {
			return "", addr.String()
		}
		return "", ""
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", ""
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if ipv4Label == "" {
				ipv4Label = ip4.String()
			}
			continue
		}
		ip16 := ip.To16()
		if ip16 != nil && ipv6Label == "" {
			ipv6Label = ip16.String()
		}
		if ipv4Label != "" && ipv6Label != "" {
			break
		}
	}
	return ipv4Label, ipv6Label
}

func pingIPv4(dst *net.IPAddr, timeout time.Duration, echoCount int) (pingResult, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return pingResult{}, err
	}
	defer c.Close()
	return pingWithConn(c, 1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, dst, timeout, echoCount)
}

func pingIPv6(dst *net.IPAddr, timeout time.Duration, echoCount int) (pingResult, error) {
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return pingResult{}, err
	}
	defer c.Close()
	return pingWithConn(c, 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, dst, timeout, echoCount)
}

func pingWithConn(
	c *icmp.PacketConn,
	parseProto int,
	requestType icmp.Type,
	replyType icmp.Type,
	dst net.Addr,
	timeout time.Duration,
	echoCount int,
) (pingResult, error) {
	echoCount = normalizeICMPEchoCount(echoCount)
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	res := pingResult{}

	id := int(uint32(time.Now().UnixNano()) & 0xffff)
	sentAt := make(map[int]time.Time, echoCount)
	readDeadline := time.Now().Add(timeout)

	interval := 0 * time.Millisecond
	if echoCount > 1 {
		interval = timeout / time.Duration(echoCount*4)
		if interval < 10*time.Millisecond {
			interval = 10 * time.Millisecond
		}
		if interval > 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
	}

	for seq := 1; seq <= echoCount; seq++ {
		if timeout > 0 && time.Now().After(readDeadline) {
			break
		}
		msg := icmp.Message{
			Type: requestType,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cm-agent")},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			res.Sent = len(sentAt)
			return res, err
		}
		now := time.Now()
		if _, err := c.WriteTo(b, dst); err != nil {
			res.Sent = len(sentAt)
			return res, err
		}
		sentAt[seq] = now
		res.Sent = len(sentAt)

		if interval > 0 && seq < echoCount {
			sleepFor := time.Until(now.Add(interval))
			if sleepFor > 0 {
				time.Sleep(sleepFor)
			}
		}
	}
	if res.Sent == 0 {
		return res, errors.New("probe timeout before sending any icmp packet")
	}

	_ = c.SetDeadline(readDeadline)
	receivedSeq := make(map[int]struct{}, res.Sent)
	var totalRTT time.Duration

	rb := make([]byte, 1500)
	for len(receivedSeq) < res.Sent {
		n, _, err := c.ReadFrom(rb)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			return res, err
		}

		rm, err := icmp.ParseMessage(parseProto, rb[:n])
		if err != nil || rm.Type != replyType {
			continue
		}
		body, ok := rm.Body.(*icmp.Echo)
		if !ok || body.ID != id {
			continue
		}
		sendTS, ok := sentAt[body.Seq]
		if !ok {
			continue
		}
		if _, seen := receivedSeq[body.Seq]; seen {
			continue
		}
		receivedSeq[body.Seq] = struct{}{}
		totalRTT += time.Since(sendTS)
	}
	res.Received = len(receivedSeq)

	if res.Received > 0 {
		res.RTT = time.Duration(int64(totalRTT) / int64(res.Received))
	}
	if res.Received == 0 {
		return res, errors.New("no echo reply received")
	}
	return res, nil
}
