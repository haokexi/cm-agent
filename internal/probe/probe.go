package probe

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
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
}

// Collector runs "blackbox-like" probes (ICMP ping and TCP connect) and emits results as metrics.
// This agent does not expose /probe; it performs the probes in-process and ships results via remote_write.
type Collector struct {
	cfg Config

	descSuccess  *prometheus.Desc
	descDuration *prometheus.Desc

	descICMPRTT *prometheus.Desc
	descTCPConn *prometheus.Desc
}

func NewCollector(cfg Config) *Collector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	labels := []string{"module", "instance"}
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
	ch <- c.descTCPConn
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	timeout := c.cfg.Timeout
	logger := c.cfg.Logger

	for _, tgt := range c.cfg.ICMP {
		tgt = strings.TrimSpace(tgt)
		if tgt == "" {
			continue
		}
		module := "icmp"
		start := time.Now()
		rtt, err := pingOnce(tgt, timeout)
		d := time.Since(start)

		if err != nil {
			logger.Debug("probe failed", "module", module, "target", tgt, "err", err)
			ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 0, module, tgt)
			ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 1, module, tgt)
		ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt)
		ch <- prometheus.MustNewConstMetric(c.descICMPRTT, prometheus.GaugeValue, rtt.Seconds(), module, tgt)
	}

	for _, tgt := range c.cfg.TCP {
		tgt = strings.TrimSpace(tgt)
		if tgt == "" {
			continue
		}
		module := "tcp_connect"
		start := time.Now()
		cd, err := tcpConnectOnce(tgt, timeout)
		d := time.Since(start)
		if err != nil {
			logger.Debug("probe failed", "module", module, "target", tgt, "err", err)
			ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 0, module, tgt)
			ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.descSuccess, prometheus.GaugeValue, 1, module, tgt)
		ch <- prometheus.MustNewConstMetric(c.descDuration, prometheus.GaugeValue, d.Seconds(), module, tgt)
		ch <- prometheus.MustNewConstMetric(c.descTCPConn, prometheus.GaugeValue, cd.Seconds(), module, tgt)
	}
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

func pingOnce(target string, timeout time.Duration) (time.Duration, error) {
	ipaddr, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return 0, err
	}
	if ipaddr.IP == nil {
		return 0, errors.New("no ip resolved")
	}

	if ipaddr.IP.To4() != nil {
		return pingIPv4(ipaddr, timeout)
	}
	return pingIPv6(ipaddr, timeout)
}

func pingIPv4(dst *net.IPAddr, timeout time.Duration) (time.Duration, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer c.Close()

	id := int(uint32(time.Now().UnixNano()) & 0xffff)
	seq := 1
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cm-agent")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	_ = c.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := c.WriteTo(b, dst); err != nil {
		return 0, err
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return 0, err
		}
		_ = peer

		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if body.ID == id && body.Seq == seq {
			return time.Since(start), nil
		}
	}
}

func pingIPv6(dst *net.IPAddr, timeout time.Duration) (time.Duration, error) {
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return 0, err
	}
	defer c.Close()

	id := int(uint32(time.Now().UnixNano()) & 0xffff)
	seq := 1
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cm-agent")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	_ = c.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := c.WriteTo(b, dst); err != nil {
		return 0, err
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return 0, err
		}
		_ = peer

		rm, err := icmp.ParseMessage(58, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if body.ID == id && body.Seq == seq {
			return time.Since(start), nil
		}
	}
}
