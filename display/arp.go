package display

import (
	"bytes"
	"fmt"
	"net"

	"github.com/gopacket/gopacket/layers"
)

// ARP rendering follows tcpdump's arp_print. The address-type detail is the
// part most easily missed: tcpdump hides it only for the ordinary
// Ethernet/IPv4 case at the default verbosity, and shows it everywhere else.

// arpHardwareNames are tcpdump's spellings for the hardware types it names.
// Anything absent here is reported by number, as tcpdump does.
var arpHardwareNames = map[layers.LinkType]string{
	1:  "Ethernet",
	6:  "TokenRing",
	7:  "ArcNet",
	15: "FrameRelay",
	23: "Strip",
	24: "IEEE 1394",
}

// arpProtocolNames are tcpdump's spellings for the protocol types that reach
// an ARP header. gopacket's own names differ for some of these.
var arpProtocolNames = map[layers.EthernetType]string{
	layers.EthernetTypeIPv4:  "IPv4",
	layers.EthernetTypeIPv6:  "IPv6",
	layers.EthernetTypeARP:   "ARP",
	layers.EthernetTypeDot1Q: "802.1Q",
	0x8035:                   "Reverse ARP",
}

func printARPLine(prefix string, arp *layers.ARP, verbosity int) error {
	// Whether the address-type detail is hidden turns only on the protocol
	// being four-byte IPv4; the hardware type and address length play no part.
	ipv4 := arp.Protocol == layers.EthernetTypeIPv4 && arp.ProtAddressSize == 4

	types := ""
	if verbosity > 0 || !ipv4 {
		types = fmt.Sprintf("%s (len %d), %s (len %d), ",
			arpHardwareName(arp.AddrType), arp.HwAddressSize,
			arpProtocolName(arp.Protocol), arp.ProtAddressSize)
	}

	// Without -v tcpdump prints no operation at all for a protocol it cannot
	// render, leaving just the type detail and the length.
	operation := ""
	if ipv4 || verbosity > 0 {
		operation = arpOperation(arp, ipv4)
	}

	length := len(arp.Contents) + len(arp.LayerPayload())
	if length == 0 {
		length = int(8 + 2*uint16(arp.HwAddressSize) + 2*uint16(arp.ProtAddressSize))
	}
	// With -e the link header has already named the protocol, so tcpdump drops
	// the tag rather than saying ARP twice on one line.
	tag := Colorize("ARP", ColorYellow) + ", "
	if renderOptions().LinkHeader {
		tag = ""
	}
	if operation == "" {
		return Outf("%s%s%slength %d\n", prefix, tag, types, length)
	}
	return Outf("%s%s%s%s, length %d\n", prefix, tag, types, operation, length)
}

// arpOperation renders the opcode-specific half of the line. Opcodes tcpdump
// answers with a hex dump are reported by number instead; see the scope note
// in the README.
func arpOperation(arp *layers.ARP, ipv4 bool) string {
	// tcpdump distinguishes the two ways a protocol address can be
	// unrenderable: the wrong protocol entirely, or IPv4 at the wrong width.
	protocolAddress := func(address []byte) string {
		switch {
		case arp.Protocol != layers.EthernetTypeIPv4:
			return "<wrong proto type>"
		case !ipv4:
			return "<wrong len>"
		default:
			return net.IP(address).String()
		}
	}
	source := net.HardwareAddr(arp.SourceHwAddress).String()
	target := net.HardwareAddr(arp.DstHwAddress).String()

	switch arp.Operation {
	case 1: // Request
		// A target hardware address that is not all zeros is worth showing:
		// the sender already believes it knows the answer.
		hint := ""
		if !bytes.Equal(arp.DstHwAddress, make([]byte, len(arp.DstHwAddress))) {
			hint = fmt.Sprintf(" (%s)", target)
		}
		// Apple's tcpdump fork labels a self-directed request "Announcement"
		// and one from an unset address "Probe". Upstream tcpdump has neither,
		// and upstream is what this follows.
		return fmt.Sprintf("Request who-has %s%s tell %s",
			protocolAddress(arp.DstProtAddress), hint, protocolAddress(arp.SourceProtAddress))
	case 2: // Reply
		return fmt.Sprintf("Reply %s is-at %s", protocolAddress(arp.SourceProtAddress), source)
	case 3: // Reverse Request
		return fmt.Sprintf("Reverse Request who-is %s tell %s", target, source)
	case 4: // Reverse Reply
		return fmt.Sprintf("Reverse Reply %s at %s", target, protocolAddress(arp.DstProtAddress))
	case 8: // Inverse Request
		return fmt.Sprintf("Inverse Request who-is %s tell %s", target, source)
	case 9: // Inverse Reply
		return fmt.Sprintf("Inverse Reply %s at %s", source, protocolAddress(arp.SourceProtAddress))
	default:
		return fmt.Sprintf("op %d", arp.Operation)
	}
}

func arpHardwareName(hardware layers.LinkType) string {
	if name, ok := arpHardwareNames[hardware]; ok {
		return name
	}
	return fmt.Sprintf("Unknown Hardware (%d)", hardware)
}

func arpProtocolName(protocol layers.EthernetType) string {
	if name, ok := arpProtocolNames[protocol]; ok {
		return name
	}
	return fmt.Sprintf("Unknown Protocol (0x%04x)", uint16(protocol))
}
