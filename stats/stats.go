// Package stats collects and prints capture session statistics:
// protocol counters, packet sizes, TCP flags, and top senders/ports.
package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"tcpdump_go/display"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Stats holds per-session capture counters and histograms.
type Stats struct {
	Total uint64
	Bytes uint64
	// Dropped is updated from the signal goroutine — always access via .Load()/.Store().
	Dropped atomic.Uint64

	IPv4    uint64
	IPv6    uint64
	ARP     uint64
	OtherL3 uint64

	TCP     uint64
	UDP     uint64
	ICMP    uint64
	OtherL4 uint64

	MinSize uint64
	MaxSize uint64
	SumSize uint64

	TcpSYN uint64
	TcpFIN uint64
	TcpRST uint64

	FirstPkt time.Time
	LastPkt  time.Time

	SrcIPCount   map[string]uint64
	DstPortCount map[string]uint64
}

// NewStats returns a zero-initialised Stats with the map fields allocated.
func NewStats() *Stats {
	return &Stats{
		SrcIPCount:   make(map[string]uint64),
		DstPortCount: make(map[string]uint64),
	}
}

// Update extracts layer information from packet and increments the appropriate
// counters. Must not be called concurrently.
func (s *Stats) Update(packet gopacket.Packet) {
	s.Total++
	size := uint64(len(packet.Data()))
	s.Bytes += size
	s.SumSize += size
	if s.MinSize == 0 || size < s.MinSize {
		s.MinSize = size
	}
	if size > s.MaxSize {
		s.MaxSize = size
	}
	ts := packet.Metadata().Timestamp
	if s.FirstPkt.IsZero() {
		s.FirstPkt = ts
	}
	s.LastPkt = ts
	nl := packet.NetworkLayer()
	switch {
	case nl == nil:
		if packet.Layer(layers.LayerTypeARP) != nil {
			s.ARP++
		} else {
			s.OtherL3++
		}
	case nl.LayerType() == layers.LayerTypeIPv4:
		s.IPv4++
		if src := nl.NetworkFlow().Src().String(); src != "" {
			s.SrcIPCount[src]++
		}
	case nl.LayerType() == layers.LayerTypeIPv6:
		s.IPv6++
		if src := nl.NetworkFlow().Src().String(); src != "" {
			s.SrcIPCount[src]++
		}
	default:
		s.OtherL3++
	}
	tl := packet.TransportLayer()
	if tl == nil {
		if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
			s.ICMP++
		}
		return
	}
	switch tl.LayerType() {
	case layers.LayerTypeTCP:
		s.TCP++
		tcp, _ := tl.(*layers.TCP)
		if tcp != nil {
			if tcp.SYN {
				s.TcpSYN++
			}
			if tcp.FIN {
				s.TcpFIN++
			}
			if tcp.RST {
				s.TcpRST++
			}
			s.DstPortCount[fmt.Sprintf("%d", tcp.DstPort)]++
		}
	case layers.LayerTypeUDP:
		s.UDP++
		udp, _ := tl.(*layers.UDP)
		if udp != nil {
			s.DstPortCount[fmt.Sprintf("%d", udp.DstPort)]++
		}
	default:
		if strings.Contains(tl.LayerType().String(), "ICMP") {
			s.ICMP++
		} else {
			s.OtherL4++
		}
	}
}

// Pct returns "X.X%" for part/total, or "—" when total is zero.
func Pct(part, total uint64) string {
	if total == 0 {
		return "\u2014"
	}
	return fmt.Sprintf("%.1f%%", float64(part)/float64(total)*100)
}

// TopN returns the n keys from m with the highest values, formatted as
// "key                 count" (left-padded to 20 chars).
func TopN(m map[string]uint64, n int) []string {
	type kv struct {
		key string
		val uint64
	}
	kvs := make([]kv, 0, len(m))
	for k, v := range m {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool {
		return kvs[i].val > kvs[j].val
	})
	result := make([]string, 0, n)
	for i := 0; i < n && i < len(kvs); i++ {
		result = append(result, fmt.Sprintf("%-20s %d", kvs[i].key, kvs[i].val))
	}
	return result
}

// Print writes the full session summary (duration, packet counts, protocol
// breakdown, top senders, top destination ports) to the buffered output.
func (s *Stats) Print() {
	dur := s.LastPkt.Sub(s.FirstPkt)
	durStr := dur.Round(time.Millisecond).String()
	if dur <= 0 {
		durStr = "< 1ms"
	}
	var pktPerSec, kbps float64
	if dur > 0 {
		secs := dur.Seconds()
		pktPerSec = float64(s.Total) / secs
		kbps = float64(s.Bytes) * 8 / secs / 1000
	}
	var avgSize uint64
	if s.Total > 0 {
		avgSize = s.SumSize / s.Total
	}
	sep := display.Colorize("\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500", display.ColorCyan)
	hdr := func(title string) {
		display.Outln(display.Colorize("\n\u2500\u2500 "+title+" ", display.ColorCyan) + display.Colorize(strings.Repeat("\u2500", max(0, 44-len(title)-4)), display.ColorCyan))
	}
	display.Outln(display.Colorize("\n\u2500\u2500 Session summary \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500", display.ColorCyan))
	display.Outf("  Duration         : %s\n", durStr)
	display.Outf("  Packets total    : %d  (%.0f pkt/s)\n", s.Total, pktPerSec)
	display.Outf("  Bytes total      : %d  (%.1f kbps)\n", s.Bytes, kbps)
	display.Outf("  Packet size      : min=%d  avg=%d  max=%d B\n", s.MinSize, avgSize, s.MaxSize)
	if dropped := s.Dropped.Load(); dropped > 0 {
		display.Outf("  Dropped (pcap)   : %s\n", display.Colorize(fmt.Sprintf("%d", dropped), display.ColorRed))
	}
	hdr("Protocol hierarchy")
	display.Outf("  %-12s %8s  %6s\n", "Protocol", "Packets", "Share")
	display.Outln(display.Colorize("  "+strings.Repeat("-", 30), display.ColorGray))
	if s.IPv4 > 0 {
		display.Outf("  %-12s %8d  %6s\n", "IPv4", s.IPv4, Pct(s.IPv4, s.Total))
	}
	if s.IPv6 > 0 {
		display.Outf("  %-12s %8d  %6s\n", "IPv6", s.IPv6, Pct(s.IPv6, s.Total))
	}
	if s.ARP > 0 {
		display.Outf("  %-12s %8d  %6s\n", "ARP", s.ARP, Pct(s.ARP, s.Total))
	}
	if s.OtherL3 > 0 {
		display.Outf("  %-12s %8d  %6s\n", "Other L3", s.OtherL3, Pct(s.OtherL3, s.Total))
	}
	display.Outln(display.Colorize("  "+strings.Repeat("-", 30), display.ColorGray))
	if s.TCP > 0 {
		display.Outf("  %-12s %8d  %6s\n", "TCP", s.TCP, Pct(s.TCP, s.Total))
	}
	if s.UDP > 0 {
		display.Outf("  %-12s %8d  %6s\n", "UDP", s.UDP, Pct(s.UDP, s.Total))
	}
	if s.ICMP > 0 {
		display.Outf("  %-12s %8d  %6s\n", "ICMP", s.ICMP, Pct(s.ICMP, s.Total))
	}
	if s.OtherL4 > 0 {
		display.Outf("  %-12s %8d  %6s\n", "Other L4", s.OtherL4, Pct(s.OtherL4, s.Total))
	}
	if s.TCP > 0 {
		hdr("TCP flags")
		display.Outf("  SYN: %d  FIN: %d  RST: %d\n", s.TcpSYN, s.TcpFIN, s.TcpRST)
	}
	if len(s.SrcIPCount) > 0 {
		hdr("Top 5 senders")
		for _, line := range TopN(s.SrcIPCount, 5) {
			display.Outf("  %s\n", line)
		}
	}
	if len(s.DstPortCount) > 0 {
		hdr("Top 5 destination ports")
		for _, line := range TopN(s.DstPortCount, 5) {
			display.Outf("  %s\n", line)
		}
	}
	display.Outln("\n" + sep)
	display.FlushOut()
}
