package agentinfo

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricName is a low-cardinality "info" metric used by the server to enrich node metadata (e.g. IPs).
// It should be present in every push from cm-agent.
const MetricName = "cm_agent_node_info"

type Collector struct {
	desc *prometheus.Desc
}

func New() *Collector {
	return &Collector{
		desc: prometheus.NewDesc(
			MetricName,
			"cm-agent node identity/network info (labels: ipv4, ipv6).",
			[]string{"ipv4", "ipv6"},
			nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ipv4, ipv6 := pickIPs()
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, ipv4, ipv6)
}

func pickIPs() (ipv4 string, ipv6 string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}

	for _, iface := range ifaces {
		// Skip down/loopback interfaces.
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil {
				continue
			}
			ip = ip.To16()
			if ip == nil {
				continue
			}
			// Skip unspecified/multicast.
			if ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				// Skip link-local 169.254.0.0/16.
				if ip4[0] == 169 && ip4[1] == 254 {
					continue
				}
				if ipv4 == "" {
					ipv4 = ip4.String()
				}
				continue
			}

			// IPv6
			if len(ip) == net.IPv6len {
				// Skip link-local fe80::/10.
				if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
					continue
				}
				if ipv6 == "" {
					ipv6 = ip.String()
				}
			}
		}

		if ipv4 != "" && ipv6 != "" {
			return ipv4, ipv6
		}
	}
	return ipv4, ipv6
}
