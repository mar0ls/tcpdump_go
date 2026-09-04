// Package stats collects and prints capture session statistics:
// protocol counters, packet sizes, TCP flags, and top senders/ports.
package stats

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"tcpdump_go/display"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Stats holds per-session capture counters and histograms.
type Stats struct {
	Total     uint64
	Bytes     uint64 // captured bytes; retained for API compatibility
	WireBytes uint64
	// Dropped is filled in from libpcap once the capture loop has finished.
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

	TCPSYN uint64
	TCPFIN uint64
	TCPRST uint64

	FirstPkt time.Time
	LastPkt  time.Time

	// SrcIPCount is keyed by gopacket's endpoint value, so counting a packet
	// costs no string allocation; only the printed entries are formatted.
	SrcIPCount map[gopacket.Endpoint]uint64
	// UntrackedSrcIPs counts packets whose source was not recorded because the
	// address table was already full.
	UntrackedSrcIPs uint64
	// DstPortCount is keyed by port number, which bounds it at 64Ki entries.
	DstPortCount map[uint16]uint64
}

// maxTrackedSrcIPs bounds the address table. A long capture on a busy link
// would otherwise grow it without limit, and only the top few are ever shown.
const maxTrackedSrcIPs = 65536

// NewStats returns a zeroed Stats ready for use.
func NewStats() *Stats {
	return &Stats{
		SrcIPCount:   make(map[gopacket.Endpoint]uint64),
		DstPortCount: make(map[uint16]uint64),
	}
}

// Update increments counters from packet. Not goroutine-safe.
func (s *Stats) Update(packet gopacket.Packet) {
	s.Total++
	size := uint64(len(packet.Data()))
	wireSize := size
	if metadata := packet.Metadata(); metadata != nil {
		if metadata.CaptureLength > 0 {
			size = uint64(metadata.CaptureLength)
		}
		if metadata.Length > 0 {
			wireSize = uint64(metadata.Length)
		}
	}
	s.Bytes += size
	s.WireBytes += wireSize
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
		s.countSrc(nl.NetworkFlow().Src())
	case nl.LayerType() == layers.LayerTypeIPv6:
		s.IPv6++
		s.countSrc(nl.NetworkFlow().Src())
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
				s.TCPSYN++
			}
			if tcp.FIN {
				s.TCPFIN++
			}
			if tcp.RST {
				s.TCPRST++
			}
			s.DstPortCount[uint16(tcp.DstPort)]++
		}
	case layers.LayerTypeUDP:
		s.UDP++
		udp, _ := tl.(*layers.UDP)
		if udp != nil {
			s.DstPortCount[uint16(udp.DstPort)]++
		}
	default:
		if strings.Contains(tl.LayerType().String(), "ICMP") {
			s.ICMP++
		} else {
			s.OtherL4++
		}
	}
}

// countSrc records one packet from src. Beyond maxTrackedSrcIPs distinct
// addresses it stops adding keys and counts the rest in UntrackedSrcIPs, so
// the table stays bounded without the totals quietly losing packets.
func (s *Stats) countSrc(src gopacket.Endpoint) {
	if len(src.Raw()) == 0 {
		return
	}
	if _, seen := s.SrcIPCount[src]; !seen && len(s.SrcIPCount) >= maxTrackedSrcIPs {
		s.UntrackedSrcIPs++
		return
	}
	s.SrcIPCount[src]++
}

// Pct returns "X.X%" for part/total, or "—" when total is zero.
func Pct(part, total uint64) string {
	if total == 0 {
		return "\u2014"
	}
	return fmt.Sprintf("%.1f%%", float64(part)/float64(total)*100)
}

// TopN returns the top n entries from m, sorted by value descending. Keys are
// formatted here rather than on the counting path, which is why the counters
// can use allocation-free key types.
func TopN[K comparable](m map[K]uint64, n int) []string {
	type kv struct {
		key string
		val uint64
	}
	kvs := make([]kv, 0, len(m))
	for k, v := range m {
		kvs = append(kvs, kv{fmt.Sprint(k), v})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].val == kvs[j].val {
			return kvs[i].key < kvs[j].key
		}
		return kvs[i].val > kvs[j].val
	})
	result := make([]string, 0, n)
	for i := 0; i < n && i < len(kvs); i++ {
		result = append(result, fmt.Sprintf("%-20s %d", kvs[i].key, kvs[i].val))
	}
	return result
}

// Print writes the session summary to buffered output.
func (s *Stats) Print() error {
	dur := s.LastPkt.Sub(s.FirstPkt)
	durStr := dur.Round(time.Millisecond).String()
	if dur <= 0 {
		durStr = "< 1ms"
	}
	var pktPerSec, kbps float64
	if dur > 0 {
		secs := dur.Seconds()
		pktPerSec = float64(s.Total) / secs
		kbps = float64(s.WireBytes) * 8 / secs / 1000
	}
	var avgSize uint64
	if s.Total > 0 {
		avgSize = s.SumSize / s.Total
	}
	var output strings.Builder
	sep := display.Colorize("\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500", display.ColorCyan)
	hdr := func(title string) {
		fmt.Fprintln(&output, display.Colorize("\n\u2500\u2500 "+title+" ", display.ColorCyan)+display.Colorize(strings.Repeat("\u2500", max(0, 44-len(title)-4)), display.ColorCyan))
	}
	fmt.Fprintln(&output, display.Colorize("\n\u2500\u2500 Session summary \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500", display.ColorCyan))
	fmt.Fprintf(&output, "  Duration         : %s\n", durStr)
	fmt.Fprintf(&output, "  Packets total    : %d  (%.0f pkt/s)\n", s.Total, pktPerSec)
	fmt.Fprintf(&output, "  Bytes captured   : %d\n", s.Bytes)
	fmt.Fprintf(&output, "  Bytes on wire    : %d  (%.1f kbps)\n", s.WireBytes, kbps)
	fmt.Fprintf(&output, "  Captured size    : min=%d  avg=%d  max=%d B\n", s.MinSize, avgSize, s.MaxSize)
	if dropped := s.Dropped.Load(); dropped > 0 {
		fmt.Fprintf(&output, "  Dropped (pcap)   : %s\n", display.Colorize(fmt.Sprintf("%d", dropped), display.ColorRed))
	}
	hdr("Protocol hierarchy")
	fmt.Fprintf(&output, "  %-12s %8s  %6s\n", "Protocol", "Packets", "Share")
	fmt.Fprintln(&output, display.Colorize("  "+strings.Repeat("-", 30), display.ColorGray))
	if s.IPv4 > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "IPv4", s.IPv4, Pct(s.IPv4, s.Total))
	}
	if s.IPv6 > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "IPv6", s.IPv6, Pct(s.IPv6, s.Total))
	}
	if s.ARP > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "ARP", s.ARP, Pct(s.ARP, s.Total))
	}
	if s.OtherL3 > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "Other L3", s.OtherL3, Pct(s.OtherL3, s.Total))
	}
	fmt.Fprintln(&output, display.Colorize("  "+strings.Repeat("-", 30), display.ColorGray))
	if s.TCP > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "TCP", s.TCP, Pct(s.TCP, s.Total))
	}
	if s.UDP > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "UDP", s.UDP, Pct(s.UDP, s.Total))
	}
	if s.ICMP > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "ICMP", s.ICMP, Pct(s.ICMP, s.Total))
	}
	if s.OtherL4 > 0 {
		fmt.Fprintf(&output, "  %-12s %8d  %6s\n", "Other L4", s.OtherL4, Pct(s.OtherL4, s.Total))
	}
	if s.TCP > 0 {
		hdr("TCP flags")
		fmt.Fprintf(&output, "  SYN: %d  FIN: %d  RST: %d\n", s.TCPSYN, s.TCPFIN, s.TCPRST)
	}
	if len(s.SrcIPCount) > 0 {
		hdr("Top 5 senders")
		for _, line := range TopN(s.SrcIPCount, 5) {
			fmt.Fprintf(&output, "  %s\n", line)
		}
		if s.UntrackedSrcIPs > 0 {
			fmt.Fprintf(&output, "  (%d packets from addresses past the %d tracked)\n", s.UntrackedSrcIPs, maxTrackedSrcIPs)
		}
	}
	if len(s.DstPortCount) > 0 {
		hdr("Top 5 destination ports")
		for _, line := range TopN(s.DstPortCount, 5) {
			fmt.Fprintf(&output, "  %s\n", line)
		}
	}
	fmt.Fprintln(&output, "\n"+sep)
	return errors.Join(display.Outf("%s", output.String()), display.FlushOut())
}
