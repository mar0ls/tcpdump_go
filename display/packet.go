package display

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// RenderOptions controls tcpdump-compatible presentation details that apply
// to a complete capture session.
type RenderOptions struct {
	LinkHeader              bool // -e
	ShowPacketNumber        bool // -# / --number
	AbsoluteSequenceNumbers bool // -S
	NumericPorts            bool // -n/-nn
}

type tcpConversation struct {
	firstAddress, secondAddress string
	firstPort, secondPort       uint16
}

type tcpSequenceBase struct {
	first, second uint32
}

// maxTrackedTCPFlows bounds the relative-sequence table.
const maxTrackedTCPFlows = 8192

// ConfigureRenderer applies options to the default printer and clears its
// relative TCP sequence state.
func ConfigureRenderer(options RenderOptions) {
	defaultPrinter.Configure(options)
}

// ResetRenderer restores the package defaults and clears per-flow state.
func ResetRenderer() {
	defaultPrinter.Reset()
}

func renderOptions() RenderOptions {
	return defaultPrinter.renderOptions()
}

// FormatTS formats a packet timestamp according to tcpdump's timestamp modes.
// displayZone is the zone timestamps are rendered in. It exists so tests can
// pin a zone without assigning to time.Local, which every time.Now() in the
// process reads and which therefore races with any background goroutine.
var displayZone = time.Local

func FormatTS(ts, prevTS time.Time, mode TSMode) string {
	switch mode {
	case TSNone:
		return ""
	case TSUnix:
		return Colorize(formatSignedMicros(ts.UnixMicro()), ColorGray)
	case TSDelta:
		if prevTS.IsZero() {
			return Colorize("00:00:00.000000", ColorGray)
		}
		return Colorize(formatSignedDuration(ts.Sub(prevTS)), ColorGray)
	case TSDateTime:
		return Colorize(ts.In(displayZone).Format("2006-01-02 15:04:05.000000"), ColorGray)
	default:
		return Colorize(ts.In(displayZone).Format("15:04:05.000000"), ColorGray)
	}
}

func formatSignedMicros(micros int64) string {
	negative := micros < 0
	var magnitude uint64
	if negative {
		magnitude = uint64(-(micros + 1)) + 1 //nolint:gosec // two's-complement negation of a negative int64
	} else {
		magnitude = uint64(micros)
	}
	sign := ""
	if negative {
		sign = "-"
	}
	return fmt.Sprintf("%s%d.%06d", sign, magnitude/1_000_000, magnitude%1_000_000)
}

func formatSignedDuration(duration time.Duration) string {
	negative := duration < 0
	var magnitude uint64
	if negative {
		magnitude = uint64(-(duration + 1)) + 1 //nolint:gosec // two's-complement negation of a negative duration
	} else {
		magnitude = uint64(duration)
	}
	totalMicros := magnitude / uint64(time.Microsecond)
	hours := totalMicros / 3_600_000_000
	minutes := totalMicros / 60_000_000 % 60
	seconds := totalMicros / 1_000_000 % 60
	micros := totalMicros % 1_000_000
	sign := ""
	if negative {
		sign = "-"
	}
	return fmt.Sprintf("%s%02d:%02d:%02d.%06d", sign, hours, minutes, seconds, micros)
}

// PrintPacket dispatches packet rendering based on viewMode and tsMode.
func PrintPacket(num uint64, packet gopacket.Packet, ts, prevTS time.Time, viewMode ViewMode, tsMode TSMode, verbosity int, disableDNS bool) error {
	tsStr := FormatTS(ts, prevTS, tsMode)
	printHeader := func() error {
		if verbosity > 0 || viewMode == ViewVerbose {
			return PrintVerbose(num, packet, tsStr, verbosity, disableDNS)
		}
		if viewMode == ViewQuick {
			return printPacketLine(num, packet, tsStr, disableDNS, true)
		}
		return PrintNormal(num, packet, tsStr, disableDNS)
	}

	switch viewMode {
	case ViewHex, ViewHexASCII, ViewASCII:
		if err := printHeader(); err != nil {
			return err
		}
		data := PacketPayload(packet)
		switch viewMode {
		case ViewHex:
			return PrintHex(data)
		case ViewHexASCII:
			return PrintHexASCII(data)
		default:
			return PrintASCII(data)
		}
	case ViewHexLink, ViewHexASCIILink:
		if err := printHeader(); err != nil {
			return err
		}
		if viewMode == ViewHexLink {
			return PrintHex(packet.Data())
		}
		return PrintHexASCII(packet.Data())
	default:
		return printHeader()
	}
}

// PrintNormal prints a compact one-line packet summary.
func PrintNormal(num uint64, packet gopacket.Packet, tsStr string, disableDNS bool) error {
	return printPacketLine(num, packet, tsStr, disableDNS, false)
}

func printPacketLine(num uint64, packet gopacket.Packet, tsStr string, disableDNS, quick bool) error {
	prefix := packetPrefix(num, tsStr, packet, quick)
	nl, done, err := printWithoutIP(prefix, packet, disableDNS, 0)
	if done {
		return err
	}
	src, dst := networkEndpoints(nl, disableDNS)
	if fragment := fragmentSummary(packet, nl); fragment != "" {
		return Outf("%s%s%s > %s: %s\n", prefix, ipTag(nl), Colorize(src, ColorGreen), Colorize(dst, ColorRed), fragment)
	}

	if quick {
		return Outf("%s%s%s\n", prefix, ipTag(nl), quickSummary(packet, nl, src, dst))
	}
	return Outf("%s%s%s\n", prefix, ipTag(nl), transportSummary(packet, nl, src, dst, 0))
}

// PrintVerbose prints IP metadata followed by the protocol summary.
func PrintVerbose(num uint64, packet gopacket.Packet, tsStr string, verbosity int, disableDNS bool) error {
	prefix := packetPrefix(num, tsStr, packet, false)
	nl, done, err := printWithoutIP(prefix, packet, disableDNS, verbosity)
	if done {
		return err
	}
	src, dst := networkEndpoints(nl, disableDNS)
	meta := ipMetadata(nl)
	if fragment := fragmentSummary(packet, nl); fragment != "" {
		return Outf("%s%s%s\n    %s > %s: %s\n", prefix, ipTag(nl), meta, Colorize(src, ColorGreen), Colorize(dst, ColorRed), fragment)
	}
	return Outf("%s%s%s\n    %s\n", prefix, ipTag(nl), meta, transportSummary(packet, nl, src, dst, verbosity))
}

// udpPayloadLength prefers the header's length field, which stays correct
// when the capture is truncated below the payload.
func udpPayloadLength(udp *layers.UDP) int {
	if udp.Length >= 8 {
		return int(udp.Length) - 8
	}
	return max(0, len(udp.LayerPayload()))
}

// ipTag is the "IP"/"IP6" label before the addresses. With -e the link header
// already names the protocol, and tcpdump drops the tag there.
func ipTag(nl gopacket.NetworkLayer) string {
	if renderOptions().LinkHeader {
		return ""
	}
	return Colorize(IPLayerName(nl), ColorYellow) + " "
}

// printWithoutIP renders the cases both packet renderers share: a header
// decode failure, ARP, and frames with no network layer. It returns the
// network layer when there is one left to print.
func printWithoutIP(prefix string, packet gopacket.Packet, disableDNS bool, verbosity int) (gopacket.NetworkLayer, bool, error) {
	if marker, endpoints, ok := decodeFailure(packet, disableDNS); ok {
		if endpoints != "" {
			return nil, true, Outf("%s%s: %s\n", prefix, endpoints, marker)
		}
		return nil, true, Outf("%s%s\n", prefix, marker)
	}
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			return nil, true, Outf("%sARP [invalid]\n", prefix)
		}
		return nil, true, printARPLine(prefix, arp, verbosity)
	}
	nl := packet.NetworkLayer()
	if nl == nil {
		if dl := packet.LinkLayer(); dl != nil {
			return nil, true, Outf("%s%s length %d\n", prefix, Colorize(dl.LayerType().String(), ColorYellow), wireLength(packet))
		}
		return nil, true, Outf("%sunknown link type, length %d\n", prefix, wireLength(packet))
	}
	return nl, false, nil
}

func packetPrefix(num uint64, tsStr string, packet gopacket.Packet, quick bool) string {
	options := renderOptions()
	parts := make([]string, 0, 3)
	if options.ShowPacketNumber {
		parts = append(parts, Colorize(fmt.Sprintf("#%-6d", num), ColorGray))
	}
	if tsStr != "" {
		parts = append(parts, tsStr)
	}
	prefix := ""
	if len(parts) > 0 {
		prefix = strings.Join(parts, " ") + " "
	}
	if options.LinkHeader {
		prefix += linkHeader(packet, quick)
	}
	return prefix
}

func linkHeader(packet gopacket.Packet, quick bool) string {
	if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
		if eth, ok := layer.(*layers.Ethernet); ok {
			etherType := eth.EthernetType
			vlan := ""
			if dotLayer := packet.Layer(layers.LayerTypeDot1Q); dotLayer != nil {
				if dot, ok := dotLayer.(*layers.Dot1Q); ok {
					vlan = fmt.Sprintf(", vlan %d", dot.VLANIdentifier)
					etherType = dot.Type
				}
			}
			if quick {
				return fmt.Sprintf("%s > %s, %s%s, length %d: ", eth.SrcMAC, eth.DstMAC, etherType, vlan, wireLength(packet))
			}
			return fmt.Sprintf("%s > %s, ethertype %s (0x%04x)%s, length %d: ",
				eth.SrcMAC, eth.DstMAC, etherType, uint16(etherType), vlan, wireLength(packet))
		}
	}
	if link := packet.LinkLayer(); link != nil {
		flow := link.LinkFlow()
		return fmt.Sprintf("%s > %s, %s, length %d: ", flow.Src(), flow.Dst(), link.LayerType(), wireLength(packet))
	}
	return ""
}

func wireLength(packet gopacket.Packet) int {
	if packet != nil && packet.Metadata() != nil && packet.Metadata().Length > 0 {
		return packet.Metadata().Length
	}
	return len(packet.Data())
}

func decodeFailure(packet gopacket.Packet, disableDNS bool) (marker, endpoints string, handled bool) {
	errorLayer := packet.ErrorLayer()
	if errorLayer == nil {
		return "", "", false
	}
	protocol := failedProtocol(packet, errorLayer)
	// A decoder failure above a complete transport header (for example malformed
	// DNS) must not erase otherwise valid TCP/UDP metadata. Only header failures
	// are handled here.
	if protocol == "" {
		return "", "", false
	}
	marker = Colorize("[|"+protocol+"]", ColorYellow)
	nl := packet.NetworkLayer()
	if nl == nil {
		return marker, "", true
	}
	src, dst := networkEndpoints(nl, disableDNS)
	failedData := errorLayer.LayerContents()
	if len(failedData) < 4 && len(nl.LayerPayload()) >= 4 {
		failedData = nl.LayerPayload()
	}
	if (protocol == "tcp" || protocol == "udp" || protocol == "sctp") && len(failedData) >= 4 {
		sport := binary.BigEndian.Uint16(failedData[:2])
		dport := binary.BigEndian.Uint16(failedData[2:4])
		return marker, fmt.Sprintf("%s.%s > %s.%s", Colorize(src, ColorGreen), portName(protocol, sport), Colorize(dst, ColorRed), portName(protocol, dport)), true
	}
	return marker, fmt.Sprintf("%s > %s", Colorize(src, ColorGreen), Colorize(dst, ColorRed)), true
}

func failedProtocol(packet gopacket.Packet, errorLayer gopacket.ErrorLayer) string {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok && (len(tcp.LayerContents()) < 20 || int(tcp.DataOffset)*4 > len(tcp.LayerContents())) {
			return "tcp"
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok && len(udp.LayerContents()) < 8 {
			return "udp"
		}
	}
	if sctpLayer := packet.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		if sctp, ok := sctpLayer.(*layers.SCTP); ok && len(sctp.LayerContents()) < 12 {
			return "sctp"
		}
	}

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		if ip, ok := ipv4Layer.(*layers.IPv4); ok {
			headerLength := int(ip.IHL) * 4
			if headerLength < 20 || len(ip.LayerContents()) < headerLength {
				return "ip"
			}
			if packet.TransportLayer() == nil {
				marker := protocolMarker(ip.Protocol)
				if marker == "ip" && !packet.Metadata().Truncated {
					return ""
				}
				return marker
			}
		}
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		if ip, ok := ipv6Layer.(*layers.IPv6); ok {
			if len(ip.LayerContents()) < 40 {
				return "ip6"
			}
			if packet.TransportLayer() == nil {
				marker := protocolMarker(ip.NextHeader)
				if marker == "ip" && !packet.Metadata().Truncated {
					return ""
				}
				return marker
			}
		}
	}
	if packet.NetworkLayer() == nil {
		if packet.LinkLayer() == nil {
			return "ether"
		}
		text := strings.ToLower(errorLayer.Error().Error())
		switch {
		case strings.Contains(text, "ipv4") || strings.Contains(text, "ip header"):
			return "ip"
		case strings.Contains(text, "ipv6"):
			return "ip6"
		default:
			return strings.ToLower(packet.LinkLayer().LayerType().String())
		}
	}
	return ""
}

func protocolMarker(protocol layers.IPProtocol) string {
	switch protocol {
	case layers.IPProtocolTCP:
		return "tcp"
	case layers.IPProtocolUDP:
		return "udp"
	case layers.IPProtocolSCTP:
		return "sctp"
	case layers.IPProtocolICMPv4:
		return "icmp"
	case layers.IPProtocolICMPv6:
		return "icmp6"
	default:
		return "ip"
	}
}

func networkEndpoints(nl gopacket.NetworkLayer, disableDNS bool) (string, string) {
	src, dst := nl.NetworkFlow().Endpoints()
	srcStr, dstStr := src.String(), dst.String()
	if !disableDNS {
		srcStr = ResolveIP(srcStr)
		dstStr = ResolveIP(dstStr)
	}
	return srcStr, dstStr
}

func transportSummary(packet gopacket.Packet, nl gopacket.NetworkLayer, src, dst string, verbosity int) string {
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		if tcp, ok := layer.(*layers.TCP); ok {
			return tcpSummary(packet, nl, src, dst, tcp, verbosity)
		}
	}
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		if udp, ok := layer.(*layers.UDP); ok {
			length := len(udp.LayerPayload())
			if udp.Length >= 8 {
				length = int(udp.Length) - 8
			}
			// The NTP printer renders a short or malformed message the way
			// tcpdump does, so the generic decoder-failure path must not
			// pre-empt it.
			isNTP := ntpPorts[uint16(udp.SrcPort)] || ntpPorts[uint16(udp.DstPort)]
			if failure := applicationFailure(packet, udp.SrcPort == 53 || udp.DstPort == 53, len(udp.LayerPayload())); failure != "" && !isNTP {
				if verbosity > 1 {
					failure = udpChecksumNote(nl, udp) + failure
				}
				return fmt.Sprintf("%s.%s > %s.%s: %s", Colorize(src, ColorGreen), portName("udp", uint16(udp.SrcPort)), Colorize(dst, ColorRed), portName("udp", uint16(udp.DstPort)), failure)
			}
			body := fmt.Sprintf("UDP, length %d", max(0, length))
			if app := applicationSummary(packet, uint16(udp.SrcPort), uint16(udp.DstPort), udp.LayerPayload(), max(0, length), verbosity, true); app != "" {
				body = app
			}
			if verbosity > 1 {
				body = udpChecksumNote(nl, udp) + body
			}
			return fmt.Sprintf("%s.%s > %s.%s: %s", Colorize(src, ColorGreen), portName("udp", uint16(udp.SrcPort)), Colorize(dst, ColorRed), portName("udp", uint16(udp.DstPort)), body)
		}
	}
	if layer := packet.Layer(layers.LayerTypeSCTP); layer != nil {
		if sctp, ok := layer.(*layers.SCTP); ok {
			length := max(0, transportSegmentLength(nl, sctp)-12)
			return fmt.Sprintf("%s.%s > %s.%s: sctp, length %d", Colorize(src, ColorGreen), portName("sctp", uint16(sctp.SrcPort)), Colorize(dst, ColorRed), portName("sctp", uint16(sctp.DstPort)), length)
		}
	}
	if layer := packet.Layer(layers.LayerTypeICMPv4); layer != nil {
		if icmp, ok := layer.(*layers.ICMPv4); ok {
			return fmt.Sprintf("%s > %s: %s", Colorize(src, ColorGreen), Colorize(dst, ColorRed), icmp4Summary(icmp, transportSegmentLength(nl, icmp)))
		}
	}
	if layer := packet.Layer(layers.LayerTypeICMPv6); layer != nil {
		if icmp, ok := layer.(*layers.ICMPv6); ok {
			return fmt.Sprintf("%s > %s: %s", Colorize(src, ColorGreen), Colorize(dst, ColorRed), icmp6Summary(packet, icmp, transportSegmentLength(nl, icmp)))
		}
	}
	return fmt.Sprintf("%s > %s: %s, length %d", Colorize(src, ColorGreen), Colorize(dst, ColorRed), genericIPProtocol(nl), ipPayloadLength(nl))
}

func quickSummary(packet gopacket.Packet, nl gopacket.NetworkLayer, src, dst string) string {
	// tcpdump keeps the full "UDP, length N" wording even in quick mode.
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		if udp, ok := layer.(*layers.UDP); ok {
			return fmt.Sprintf("%s.%s > %s.%s: UDP, length %d",
				Colorize(src, ColorGreen), portName("udp", uint16(udp.SrcPort)),
				Colorize(dst, ColorRed), portName("udp", uint16(udp.DstPort)), udpPayloadLength(udp))
		}
	}
	if tl := packet.TransportLayer(); tl != nil {
		sport, dport := displayPorts(tl)
		if sport != "" {
			return fmt.Sprintf("%s.%s > %s.%s: %s %d", src, sport, dst, dport, strings.ToLower(tl.LayerType().String()), len(tl.LayerPayload()))
		}
		return fmt.Sprintf("%s > %s: %s %d", src, dst, strings.ToLower(tl.LayerType().String()), len(tl.LayerPayload()))
	}
	return fmt.Sprintf("%s > %s: %s %d", src, dst, strings.ToLower(genericIPProtocol(packet.NetworkLayer())), ipPayloadLength(packet.NetworkLayer()))
}

func tcpSummary(packet gopacket.Packet, nl gopacket.NetworkLayer, src, dst string, tcp *layers.TCP, verbosity int) string {
	payloadLength := tcpPayloadLength(nl, tcp)
	flow := nl.NetworkFlow()
	seq, ack := tcpSequenceNumbers(flow.Src().String(), flow.Dst().String(), tcp)
	parts := []string{fmt.Sprintf("Flags [%s]", TCPFlagsShort(tcp))}
	if verbosity > 0 {
		if cksum := transportChecksum(nl, tcp); cksum != "" {
			parts = append(parts, cksum)
		}
	}
	if payloadLength > 0 {
		parts = append(parts, fmt.Sprintf("seq %d:%d", seq, seq+uint32(payloadLength))) //nolint:gosec // bounded by IP packet size
	} else if tcp.SYN || tcp.FIN || tcp.RST {
		parts = append(parts, fmt.Sprintf("seq %d", seq))
	}
	if tcp.ACK {
		parts = append(parts, fmt.Sprintf("ack %d", ack))
	}
	parts = append(parts, fmt.Sprintf("win %d", tcp.Window))
	if tcp.URG {
		parts = append(parts, fmt.Sprintf("urg %d", tcp.Urgent))
	}
	if options := TCPOptionsStr(tcp); options != "" {
		parts = append(parts, "options ["+options+"]")
	}
	parts = append(parts, fmt.Sprintf("length %d", payloadLength))
	if failure := applicationFailure(packet, false, payloadLength); failure != "" {
		parts = append(parts, failure)
	}
	body := strings.Join(parts, ", ")
	if app := applicationSummary(packet, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.LayerPayload(), len(tcp.LayerPayload()), verbosity, false); app != "" {
		body += ": " + app
	}
	return fmt.Sprintf("%s.%s > %s.%s: %s", Colorize(src, ColorGreen), portName("tcp", uint16(tcp.SrcPort)), Colorize(dst, ColorRed), portName("tcp", uint16(tcp.DstPort)), body)
}

// dnsHeaderSize is the fixed DNS header length tcpdump checks against.
const dnsHeaderSize = 12

func applicationFailure(packet gopacket.Packet, dns bool, payloadLength int) string {
	errorLayer := packet.ErrorLayer()
	if errorLayer == nil {
		return ""
	}
	if dns {
		// tcpdump reports a short DNS message by length, not by decoder text.
		if payloadLength < dnsHeaderSize {
			return fmt.Sprintf("domain [length %d < %d] (invalid)", payloadLength, dnsHeaderSize)
		}
		return "domain [invalid]"
	}
	message := strings.TrimSpace(errorLayer.Error().Error())
	if len(message) > 160 {
		message = message[:157] + "..."
	}
	return fmt.Sprintf("decode error [%s]", message)
}

func displayPorts(transport gopacket.TransportLayer) (string, string) {
	switch layer := transport.(type) {
	case *layers.TCP:
		return portName("tcp", uint16(layer.SrcPort)), portName("tcp", uint16(layer.DstPort))
	case *layers.UDP:
		return portName("udp", uint16(layer.SrcPort)), portName("udp", uint16(layer.DstPort))
	case *layers.SCTP:
		return portName("sctp", uint16(layer.SrcPort)), portName("sctp", uint16(layer.DstPort))
	default:
		return "", ""
	}
}

func portName(protocol string, port uint16) string {
	if renderOptions().NumericPorts {
		return fmt.Sprintf("%d", port)
	}
	var (
		name string
		ok   bool
	)
	switch protocol {
	case "tcp":
		name, ok = layers.TCPPortNames(layers.TCPPort(port))
	case "udp":
		name, ok = layers.UDPPortNames(layers.UDPPort(port))
	case "sctp":
		name, ok = layers.SCTPPortNames(layers.SCTPPort(port))
	}
	if ok && name != "" {
		return name
	}
	return fmt.Sprintf("%d", port)
}

func tcpSequenceNumbers(src, dst string, tcp *layers.TCP) (uint32, uint32) {
	return defaultPrinter.tcpSequenceNumbers(src, dst, tcp)
}

// tcpSequenceNumbers converts absolute numbers to tcpdump's relative form.
// The bases live on the printer so two sessions cannot corrupt each other's
// per-flow view.
func (p *Printer) tcpSequenceNumbers(src, dst string, tcp *layers.TCP) (uint32, uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// tcpdump only applies relative numbering after it has observed an ACK.
	// The first ACK-bearing packet (and every new SYN) establishes both
	// directional bases but is itself printed with absolute numbers.
	if p.options.AbsoluteSequenceNumbers || !tcp.ACK {
		return tcp.Seq, tcp.Ack
	}
	if len(p.seqBase) >= maxTrackedTCPFlows {
		clear(p.seqBase)
	}
	conversation, reverse := canonicalTCPConversation(src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort))
	base, ok := p.seqBase[conversation]
	if !ok || tcp.SYN {
		if reverse {
			base = tcpSequenceBase{first: tcp.Ack - 1, second: tcp.Seq}
		} else {
			base = tcpSequenceBase{first: tcp.Seq, second: tcp.Ack - 1}
		}
		p.seqBase[conversation] = base
		return tcp.Seq, tcp.Ack
	}
	if reverse {
		return tcp.Seq - base.second, tcp.Ack - base.first
	}
	return tcp.Seq - base.first, tcp.Ack - base.second
}

func canonicalTCPConversation(src, dst string, sport, dport uint16) (tcpConversation, bool) {
	reverse := sport > dport || (sport == dport && src > dst)
	if reverse {
		return tcpConversation{
			firstAddress: dst, secondAddress: src,
			firstPort: dport, secondPort: sport,
		}, true
	}
	return tcpConversation{
		firstAddress: src, secondAddress: dst,
		firstPort: sport, secondPort: dport,
	}, false
}

func tcpPayloadLength(nl gopacket.NetworkLayer, tcp *layers.TCP) int {
	headerLength := int(tcp.DataOffset) * 4
	if headerLength < 20 {
		headerLength = len(tcp.LayerContents())
	}
	if segmentLength := transportSegmentLength(nl, tcp); segmentLength >= headerLength {
		return segmentLength - headerLength
	}
	return len(tcp.LayerPayload())
}

// transportSegmentLength removes IPv6 extension headers between the network
// and transport layers while retaining the original IP-declared length. This
// reports wire payload length accurately even when a packet was snap-truncated.
func transportSegmentLength(nl gopacket.NetworkLayer, transport gopacket.Layer) int {
	ipLength := ipPayloadLength(nl)
	if nl == nil || transport == nil {
		return ipLength
	}
	transportBytes := len(transport.LayerContents()) + len(transport.LayerPayload())
	prefixLength := len(nl.LayerPayload()) - transportBytes
	if ip, ok := nl.(*layers.IPv6); ok && ip.HopByHop != nil {
		// gopacket folds Hop-by-Hop into IPv6 and removes it from LayerPayload.
		prefixLength += ip.HopByHop.ActualLength
	}
	if prefixLength > 0 && ipLength >= prefixLength {
		return ipLength - prefixLength
	}
	return ipLength
}

func ipPayloadLength(nl gopacket.NetworkLayer) int {
	switch ip := nl.(type) {
	case *layers.IPv4:
		headerLength := int(ip.IHL) * 4
		if int(ip.Length) >= headerLength {
			return int(ip.Length) - headerLength
		}
	case *layers.IPv6:
		return int(ip.Length)
	}
	if nl == nil {
		return 0
	}
	return len(nl.LayerPayload())
}

func genericIPProtocol(nl gopacket.NetworkLayer) string {
	switch ip := nl.(type) {
	case *layers.IPv4:
		return fmt.Sprintf("ip-proto-%d", uint8(ip.Protocol))
	case *layers.IPv6:
		return fmt.Sprintf("ip6-proto-%d", uint8(ip.NextHeader))
	default:
		return "unknown-proto"
	}
}

func fragmentSummary(packet gopacket.Packet, nl gopacket.NetworkLayer) string {
	if ip, ok := nl.(*layers.IPv4); ok && (ip.FragOffset > 0 || ip.Flags&layers.IPv4MoreFragments != 0) {
		flags := ""
		if ip.Flags&layers.IPv4MoreFragments != 0 {
			flags = "+"
		}
		return fmt.Sprintf("%s (frag %d:%d%s)", genericIPProtocol(nl), int(ip.FragOffset)*8, ipPayloadLength(nl), flags)
	}
	if layer := packet.Layer(layers.LayerTypeIPv6Fragment); layer != nil {
		if fragment, ok := layer.(*layers.IPv6Fragment); ok {
			more := ""
			if fragment.MoreFragments {
				more = "+"
			}
			return fmt.Sprintf("ip6-proto-%d (frag %d%s)", uint8(fragment.NextHeader), int(fragment.FragmentOffset)*8, more)
		}
	}
	return ""
}

func ipMetadata(nl gopacket.NetworkLayer) string {
	switch ip := nl.(type) {
	case *layers.IPv4:
		flags := make([]string, 0, 2)
		if ip.Flags&layers.IPv4DontFragment != 0 {
			flags = append(flags, "DF")
		}
		if ip.Flags&layers.IPv4MoreFragments != 0 {
			flags = append(flags, "+")
		}
		if len(flags) == 0 {
			flags = append(flags, "none")
		}
		return fmt.Sprintf("(tos 0x%x, ttl %d, id %d, offset %d, flags [%s], proto %s (%d), length %d%s)",
			ip.TOS, ip.TTL, ip.Id, int(ip.FragOffset)*8, strings.Join(flags, "|"), ip.Protocol, ip.Protocol, ip.Length,
			ipChecksumProblem(nl))
	case *layers.IPv6:
		return fmt.Sprintf("(class 0x%x, flowlabel 0x%x, hlim %d, next-header %s (%d), payload length %d)",
			ip.TrafficClass, ip.FlowLabel, ip.HopLimit, ip.NextHeader, ip.NextHeader, ip.Length)
	default:
		return ""
	}
}

func icmp4Summary(icmp *layers.ICMPv4, length int) string {
	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		return fmt.Sprintf("ICMP echo request, id %d, seq %d, length %d", icmp.Id, icmp.Seq, length)
	case layers.ICMPv4TypeEchoReply:
		return fmt.Sprintf("ICMP echo reply, id %d, seq %d, length %d", icmp.Id, icmp.Seq, length)
	case layers.ICMPv4TypeDestinationUnreachable:
		return fmt.Sprintf("ICMP destination unreachable (%d), length %d", icmp.TypeCode.Code(), length)
	case layers.ICMPv4TypeTimeExceeded:
		return fmt.Sprintf("ICMP time exceeded (%d), length %d", icmp.TypeCode.Code(), length)
	default:
		return fmt.Sprintf("ICMP %s, length %d", icmp.TypeCode, length)
	}
}

func icmp6Summary(packet gopacket.Packet, icmp *layers.ICMPv6, length int) string {
	typeName := fmt.Sprintf("ICMP6 %s", icmp.TypeCode)
	if icmp.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
		typeName = "ICMP6 echo request"
	} else if icmp.TypeCode.Type() == layers.ICMPv6TypeEchoReply {
		typeName = "ICMP6 echo reply"
	}
	if layer := packet.Layer(layers.LayerTypeICMPv6Echo); layer != nil {
		if echo, ok := layer.(*layers.ICMPv6Echo); ok {
			return fmt.Sprintf("%s, id %d, seq %d, length %d", typeName, echo.Identifier, echo.SeqNumber, length)
		}
	}
	return fmt.Sprintf("%s, length %d", typeName, length)
}

// TCPFlagsShort returns tcpdump's TCP flag notation.
func TCPFlagsShort(tcp *layers.TCP) string {
	var flags strings.Builder
	if tcp.FIN {
		flags.WriteByte('F')
	}
	if tcp.SYN {
		flags.WriteByte('S')
	}
	if tcp.RST {
		flags.WriteByte('R')
	}
	if tcp.PSH {
		flags.WriteByte('P')
	}
	if tcp.ACK {
		flags.WriteByte('.')
	}
	if tcp.URG {
		flags.WriteByte('U')
	}
	if tcp.ECE {
		flags.WriteByte('E')
	}
	if tcp.CWR {
		flags.WriteByte('W')
	}
	if tcp.NS {
		flags.WriteByte('A')
	}
	if flags.Len() == 0 {
		return "none"
	}
	return flags.String()
}

// TCPOptionsStr formats TCP options as a comma-separated string.
func TCPOptionsStr(tcp *layers.TCP) string {
	parts := make([]string, 0, len(tcp.Options))
	for _, option := range tcp.Options {
		switch option.OptionType {
		case layers.TCPOptionKindNop:
			parts = append(parts, "nop")
		case layers.TCPOptionKindEndList:
			// End-of-list is padding rather than useful packet information.
		case layers.TCPOptionKindMSS:
			if len(option.OptionData) == 2 {
				parts = append(parts, fmt.Sprintf("mss %d", binary.BigEndian.Uint16(option.OptionData)))
			} else {
				parts = append(parts, "mss [bad length]")
			}
		case layers.TCPOptionKindTimestamps:
			if len(option.OptionData) == 8 {
				parts = append(parts, fmt.Sprintf("TS val %d ecr %d", binary.BigEndian.Uint32(option.OptionData[:4]), binary.BigEndian.Uint32(option.OptionData[4:])))
			} else {
				parts = append(parts, "TS [bad length]")
			}
		case layers.TCPOptionKindWindowScale:
			if len(option.OptionData) == 1 {
				parts = append(parts, fmt.Sprintf("wscale %d", option.OptionData[0]))
			} else {
				parts = append(parts, "wscale [bad length]")
			}
		case layers.TCPOptionKindSACKPermitted:
			parts = append(parts, "sackOK")
		case layers.TCPOptionKindSACK:
			if len(option.OptionData)%8 != 0 {
				parts = append(parts, "sack [bad length]")
				continue
			}
			blocks := make([]string, 0, len(option.OptionData)/8)
			for offset := 0; offset < len(option.OptionData); offset += 8 {
				blocks = append(blocks, fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(option.OptionData[offset:offset+4]), binary.BigEndian.Uint32(option.OptionData[offset+4:offset+8])))
			}
			parts = append(parts, "sack "+strings.Join(blocks, " "))
		default:
			parts = append(parts, fmt.Sprintf("opt-%d", option.OptionType))
		}
	}
	return strings.Join(parts, ",")
}

// IPLayerName returns tcpdump's short IP layer name.
func IPLayerName(nl gopacket.NetworkLayer) string {
	if nl == nil {
		return ""
	}
	switch nl.LayerType() {
	case layers.LayerTypeIPv4:
		return "IP"
	case layers.LayerTypeIPv6:
		return "IP6"
	default:
		return nl.LayerType().String()
	}
}

// ExtractPorts returns source/destination ports for port-bearing transports.
func ExtractPorts(tl gopacket.TransportLayer) (sport, dport string) {
	switch transport := tl.(type) {
	case *layers.TCP:
		return fmt.Sprintf("%d", transport.SrcPort), fmt.Sprintf("%d", transport.DstPort)
	case *layers.UDP:
		return fmt.Sprintf("%d", transport.SrcPort), fmt.Sprintf("%d", transport.DstPort)
	case *layers.SCTP:
		return fmt.Sprintf("%d", transport.SrcPort), fmt.Sprintf("%d", transport.DstPort)
	default:
		return "", ""
	}
}

// ExtractTransportInfo returns protocol name and source/destination ports.
func ExtractTransportInfo(packet gopacket.Packet) (proto, sport, dport string) {
	if tl := packet.TransportLayer(); tl != nil {
		proto = tl.LayerType().String()
		sport, dport = ExtractPorts(tl)
		return proto, sport, dport
	}
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return "ICMPv4", "", ""
	}
	if packet.Layer(layers.LayerTypeICMPv6) != nil {
		return "ICMPv6", "", ""
	}
	if nl := packet.NetworkLayer(); nl != nil {
		return genericIPProtocol(nl), "", ""
	}
	return "other", "", ""
}
