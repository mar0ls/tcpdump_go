package display

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// FormatTS formats a packet timestamp according to mode.
func FormatTS(ts, prevTS time.Time, mode TSMode) string {
	switch mode {
	case TSNone:
		return ""
	case TSUnix:
		us := ts.UnixMicro()
		return Colorize(fmt.Sprintf("%d.%06d", us/1e6, us%1e6), ColorGray)
	case TSDelta:
		if prevTS.IsZero() {
			return Colorize("0.000000", ColorGray)
		}
		d := ts.Sub(prevTS)
		sec := int64(d.Seconds())
		us := (d.Nanoseconds() % 1e9) / 1e3
		if us < 0 {
			us = -us
		}
		return Colorize(fmt.Sprintf("%d.%06d", sec, us), ColorGray)
	case TSDateTime:
		return Colorize(ts.Format("2006-01-02 15:04:05.000000"), ColorGray)
	default:
		return Colorize(ts.Format("15:04:05.000000"), ColorGray)
	}
}

// PrintPacket dispatches packet rendering based on viewMode and tsMode.
func PrintPacket(num uint64, packet gopacket.Packet, ts, prevTS time.Time, viewMode ViewMode, tsMode TSMode, verbose, disableDNS bool) {
	tsStr := FormatTS(ts, prevTS, tsMode)
	switch viewMode {
	case ViewHex, ViewHexASCII:
		if verbose {
			PrintVerbose(num, packet, tsStr, disableDNS)
		} else {
			PrintNormal(num, packet, tsStr, disableDNS)
		}
		data := PacketPayload(packet)
		if viewMode == ViewHex {
			PrintHex(data)
		} else {
			PrintHexASCII(data)
		}
	case ViewHexLink, ViewHexASCIILink:
		if verbose {
			PrintVerbose(num, packet, tsStr, disableDNS)
		} else {
			PrintNormal(num, packet, tsStr, disableDNS)
		}
		data := packet.Data()
		if viewMode == ViewHexLink {
			PrintHex(data)
		} else {
			PrintHexASCII(data)
		}
	case ViewVerbose:
		PrintVerbose(num, packet, tsStr, disableDNS)
	default:
		PrintNormal(num, packet, tsStr, disableDNS)
	}
}

// PrintVerbose prints the -v style packet header (IP metadata, TCP flags, options).
func PrintVerbose(num uint64, packet gopacket.Packet, tsStr string, disableDNS bool) {
	numStr := Colorize(fmt.Sprintf("#%-6d", num), ColorGray)
	nl := packet.NetworkLayer()
	if nl == nil {
		if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
			a := arp.(*layers.ARP)
			printARPLine(numStr, tsStr, a, int(8+2*uint16(a.HwAddressSize)+2*uint16(a.ProtAddressSize)))
			return
		}
		if dl := packet.LinkLayer(); dl != nil {
			Outf("%s %s %s length %d\n", numStr, tsStr,
				Colorize(dl.LayerType().String(), ColorYellow),
				len(packet.Data()))
		}
		return
	}
	src, dst := nl.NetworkFlow().Endpoints()
	srcStr, dstStr := src.String(), dst.String()
	if !disableDNS {
		srcStr = ResolveIP(srcStr)
		dstStr = ResolveIP(dstStr)
	}
	ipMeta := ""
	switch ip := nl.(type) {
	case *layers.IPv4:
		ipFlags := ""
		if ip.Flags&layers.IPv4DontFragment != 0 {
			ipFlags = "DF"
		}
		if ip.Flags&layers.IPv4MoreFragments != 0 {
			if ipFlags != "" {
				ipFlags += "|"
			}
			ipFlags += "MF"
		}
		if ipFlags == "" {
			ipFlags = "none"
		}
		ipMeta = fmt.Sprintf("(tos 0x%x, ttl %d, id %d, offset %d, flags [%s], proto %s (%d), length %d)",
			ip.TOS, ip.TTL, ip.Id, ip.FragOffset, ipFlags, ip.Protocol, ip.Protocol, ip.Length)
	case *layers.IPv6:
		ipMeta = fmt.Sprintf("(flow 0x%x, hlim %d, proto %s, len %d)",
			ip.FlowLabel, ip.HopLimit, ip.NextHeader, ip.Length)
	}
	tl := packet.TransportLayer()
	if tl == nil {
		Outf("%s %s %s %s\n    %s > %s: length %d\n",
			numStr, tsStr, Colorize(IPLayerName(nl), ColorYellow), ipMeta,
			Colorize(srcStr, ColorGreen), Colorize(dstStr, ColorRed),
			len(packet.Data()))
		return
	}
	sport, dport := ExtractPorts(tl)
	ipProtoStr := Colorize(IPLayerName(nl), ColorYellow)
	payloadLen := len(tl.LayerPayload())
	switch tcp := tl.(type) {
	case *layers.TCP:
		flags := Colorize("["+TCPFlagsShort(tcp)+"]", ColorYellow)
		seqEnd := tcp.Seq + uint32(payloadLen) //nolint:gosec // payloadLen is capped by pcap snaplen
		opts := TCPOptionsStr(tcp)
		if opts != "" {
			opts = ", options [" + opts + "]"
		}
		Outf("%s %s %s %s\n    %s.%s > %s.%s: Flags %s, seq %d:%d, ack %d, win %d%s, length %d\n",
			numStr, tsStr, ipProtoStr, ipMeta,
			Colorize(srcStr, ColorGreen), Colorize(sport, ColorCyan),
			Colorize(dstStr, ColorRed), Colorize(dport, ColorCyan),
			flags, tcp.Seq, seqEnd, tcp.Ack, tcp.Window, opts, payloadLen)
	case *layers.UDP:
		Outf("%s %s %s %s\n    %s.%s > %s.%s: length %d\n",
			numStr, tsStr, ipProtoStr, ipMeta,
			Colorize(srcStr, ColorGreen), Colorize(sport, ColorCyan),
			Colorize(dstStr, ColorRed), Colorize(dport, ColorCyan),
			payloadLen)
	default:
		Outf("%s %s %s %s\n    %s > %s: length %d\n",
			numStr, tsStr, ipProtoStr, ipMeta,
			Colorize(srcStr, ColorGreen), Colorize(dstStr, ColorRed),
			payloadLen)
	}
}

// TCPFlagsShort returns an abbreviated TCP flag string, e.g. "SA", "F", "R".
func TCPFlagsShort(tcp *layers.TCP) string {
	var b strings.Builder
	if tcp.SYN {
		b.WriteByte('S')
	}
	if tcp.ACK {
		b.WriteByte('A')
	}
	if tcp.FIN {
		b.WriteByte('F')
	}
	if tcp.RST {
		b.WriteByte('R')
	}
	if tcp.PSH {
		b.WriteByte('P')
	}
	if tcp.URG {
		b.WriteByte('U')
	}
	if b.Len() == 0 {
		return "."
	}
	return b.String()
}

// TCPOptionsStr formats TCP options as a comma-separated string; unknown kinds render as "opt-N".
func TCPOptionsStr(tcp *layers.TCP) string {
	if len(tcp.Options) == 0 {
		return ""
	}
	parts := make([]string, 0, len(tcp.Options))
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindNop:
			parts = append(parts, "nop")
		case layers.TCPOptionKindEndList:
			// skip
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == 2 {
				mss := uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
				parts = append(parts, fmt.Sprintf("mss %d", mss))
			}
		case layers.TCPOptionKindTimestamps:
			if len(opt.OptionData) == 8 {
				val := uint32(opt.OptionData[0])<<24 | uint32(opt.OptionData[1])<<16 |
					uint32(opt.OptionData[2])<<8 | uint32(opt.OptionData[3])
				ecr := uint32(opt.OptionData[4])<<24 | uint32(opt.OptionData[5])<<16 |
					uint32(opt.OptionData[6])<<8 | uint32(opt.OptionData[7])
				parts = append(parts, fmt.Sprintf("TS val %d ecr %d", val, ecr))
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) == 1 {
				parts = append(parts, fmt.Sprintf("wscale %d", opt.OptionData[0]))
			}
		case layers.TCPOptionKindSACKPermitted:
			parts = append(parts, "sackOK")
		case layers.TCPOptionKindSACK:
			parts = append(parts, "sack")
		default:
			parts = append(parts, fmt.Sprintf("opt-%d", opt.OptionType))
		}
	}
	return strings.Join(parts, ",")
}

func printARPLine(numStr, tsStr string, arp *layers.ARP, arpLen int) {
	var op string
	switch arp.Operation {
	case layers.ARPRequest:
		op = fmt.Sprintf("Request who-has %s tell %s",
			net.IP(arp.DstProtAddress),
			net.IP(arp.SourceProtAddress))
	case layers.ARPReply:
		op = fmt.Sprintf("Reply %s is-at %s",
			net.IP(arp.SourceProtAddress),
			net.HardwareAddr(arp.SourceHwAddress))
	default:
		op = fmt.Sprintf("op %d", arp.Operation)
	}
	Outf("%s %s %s, %s, length %d\n",
		numStr, tsStr,
		Colorize("ARP", ColorYellow),
		op, arpLen)
}

// PrintNormal prints a compact one-line packet summary (default tcpdump style).
func PrintNormal(num uint64, packet gopacket.Packet, tsStr string, disableDNS bool) {
	nl := packet.NetworkLayer()
	tl := packet.TransportLayer()
	numStr := Colorize(fmt.Sprintf("#%-6d", num), ColorGray)
	if nl == nil {
		if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
			a := arp.(*layers.ARP)
			printARPLine(numStr, tsStr, a, int(8+2*uint16(a.HwAddressSize)+2*uint16(a.ProtAddressSize)))
			return
		}
		if dl := packet.LinkLayer(); dl != nil {
			Outf("%s %s %s length %d\n", numStr, tsStr,
				Colorize(dl.LayerType().String(), ColorYellow),
				len(packet.Data()))
		}
		return
	}
	src, dst := nl.NetworkFlow().Endpoints()
	srcStr, dstStr := src.String(), dst.String()
	if !disableDNS {
		srcStr = ResolveIP(srcStr)
		dstStr = ResolveIP(dstStr)
	}
	proto := Colorize(IPLayerName(nl), ColorYellow)
	if tl == nil {
		Outf("%s %s %s %s > %s: length %d\n", numStr, tsStr, proto,
			Colorize(srcStr, ColorGreen), Colorize(dstStr, ColorRed),
			len(PacketPayload(packet)))
		return
	}
	sport, dport := ExtractPorts(tl)
	protoStr := Colorize(tl.LayerType().String(), ColorYellow)
	payloadLen := len(tl.LayerPayload())
	switch tcp := tl.(type) {
	case *layers.TCP:
		flags := Colorize("["+TCPFlagsShort(tcp)+"]", ColorYellow)
		Outf("%s %s %s  %s.%s > %s.%s: Flags %s, seq %d, ack %d, win %d, length %d\n",
			numStr, tsStr, protoStr,
			Colorize(srcStr, ColorGreen), Colorize(sport, ColorCyan),
			Colorize(dstStr, ColorRed), Colorize(dport, ColorCyan),
			flags, tcp.Seq, tcp.Ack, tcp.Window, payloadLen)
	default:
		Outf("%s %s %s  %s.%s > %s.%s: length %d\n",
			numStr, tsStr, protoStr,
			Colorize(srcStr, ColorGreen), Colorize(sport, ColorCyan),
			Colorize(dstStr, ColorRed), Colorize(dport, ColorCyan),
			payloadLen)
	}
}

// IPLayerName returns "IP", "IP6", or the raw layer type string for nl.
func IPLayerName(nl gopacket.NetworkLayer) string {
	switch nl.LayerType() {
	case layers.LayerTypeIPv4:
		return "IP"
	case layers.LayerTypeIPv6:
		return "IP6"
	default:
		return nl.LayerType().String()
	}
}

// ExtractPorts returns src/dst port strings for TCP/UDP; empty for other layers.
func ExtractPorts(tl gopacket.TransportLayer) (sport, dport string) {
	switch t := tl.(type) {
	case *layers.TCP:
		return fmt.Sprintf("%d", t.SrcPort), fmt.Sprintf("%d", t.DstPort)
	case *layers.UDP:
		return fmt.Sprintf("%d", t.SrcPort), fmt.Sprintf("%d", t.DstPort)
	}
	return "", ""
}

// ExtractTransportInfo returns proto name + src/dst ports for the packet's transport layer.
func ExtractTransportInfo(packet gopacket.Packet) (proto, sport, dport string) {
	tl := packet.TransportLayer()
	if tl == nil {
		if nl := packet.NetworkLayer(); nl != nil {
			return nl.LayerType().String(), "", ""
		}
		return "other", "", ""
	}
	proto = tl.LayerType().String()
	sport, dport = ExtractPorts(tl)
	return proto, sport, dport
}
