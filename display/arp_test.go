package display

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// The expected strings come from tcpdump 4.99.1 rendering the same fields.

func arpFor(operation uint16, sha, spa, tha, tpa []byte) *layers.ARP {
	return &layers.ARP{
		AddrType: 1, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: operation,
		SourceHwAddress: sha, SourceProtAddress: spa,
		DstHwAddress: tha, DstProtAddress: tpa,
	}
}

var (
	arpMAC     = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	arpOther   = []byte{0x09, 0x09, 0x09, 0x09, 0x09, 0x09}
	arpZeroMAC = make([]byte, 6)
	arpFirst   = []byte{10, 0, 0, 1}
	arpSecond  = []byte{10, 0, 0, 2}
	arpUnset   = []byte{0, 0, 0, 0}
)

func TestARPOperationsMatchTcpdump(t *testing.T) {
	cases := []struct {
		name      string
		arp       *layers.ARP
		verbosity int
		want      string
	}{
		{
			"request", arpFor(1, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0,
			"Request who-has 10.0.0.2 tell 10.0.0.1",
		},
		// A target hardware address that is already filled in is worth showing.
		{
			"request naming a target", arpFor(1, arpMAC, arpFirst, arpOther, arpSecond), 0,
			"Request who-has 10.0.0.2 (09:09:09:09:09:09) tell 10.0.0.1",
		},
		// Apple's fork labels these "Announcement" and "Probe"; upstream
		// tcpdump, which this follows, renders them as ordinary requests.
		{
			"request for the sender's own address", arpFor(1, arpMAC, arpFirst, arpZeroMAC, arpFirst), 0,
			"Request who-has 10.0.0.1 tell 10.0.0.1",
		},
		{
			"request from an unset address", arpFor(1, arpMAC, arpUnset, arpZeroMAC, arpSecond), 0,
			"Request who-has 10.0.0.2 tell 0.0.0.0",
		},
		{
			"reply", arpFor(2, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0,
			"Reply 10.0.0.1 is-at 00:01:02:03:04:05",
		},
		{
			"reverse request", arpFor(3, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0,
			"Reverse Request who-is 00:00:00:00:00:00 tell 00:01:02:03:04:05",
		},
		{
			"reverse reply", arpFor(4, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0,
			"Reverse Reply 00:00:00:00:00:00 at 10.0.0.2",
		},
		{
			"inverse request", arpFor(8, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0,
			"Inverse Request who-is 00:00:00:00:00:00 tell 00:01:02:03:04:05",
		},
		{
			"inverse reply", arpFor(9, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0,
			"Inverse Reply 00:01:02:03:04:05 at 10.0.0.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := arpOperation(tc.arp, true); got != tc.want {
				t.Fatalf("arpOperation = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestARPAddressTypeDetailIsHiddenOnlyForPlainIPv4(t *testing.T) {
	// The suppression turns on the protocol alone: an unusual hardware type
	// still prints the short form, while a protocol that is not four-byte IPv4
	// always brings the detail out.
	cases := []struct {
		name      string
		arp       *layers.ARP
		verbosity int
		wantTypes bool
	}{
		{"plain IPv4 over Ethernet", arpFor(1, arpMAC, arpFirst, arpZeroMAC, arpSecond), 0, false},
		{"plain IPv4 under -v", arpFor(1, arpMAC, arpFirst, arpZeroMAC, arpSecond), 1, true},
		{"unusual hardware type", &layers.ARP{
			AddrType: 6, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: 1, SourceHwAddress: arpMAC, SourceProtAddress: arpFirst,
			DstHwAddress: arpZeroMAC, DstProtAddress: arpSecond,
		}, 0, false},
		{"non-IPv4 protocol", &layers.ARP{
			AddrType: 1, Protocol: layers.EthernetTypeIPv6, HwAddressSize: 6, ProtAddressSize: 16,
			Operation: 1, SourceHwAddress: arpMAC, SourceProtAddress: make([]byte, 16),
			DstHwAddress: arpZeroMAC, DstProtAddress: make([]byte, 16),
		}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, restore := CaptureOut()
			defer restore()
			mustWrite(t, printARPLine("", tc.arp, tc.verbosity))
			mustWrite(t, FlushOut())
			hasTypes := strings.Contains(buf.String(), "(len 6)")
			if hasTypes != tc.wantTypes {
				t.Fatalf("address-type detail present = %v, want %v: %q", hasTypes, tc.wantTypes, buf.String())
			}
		})
	}
}

func TestARPUnrenderableProtocolAddresses(t *testing.T) {
	// tcpdump separates the wrong protocol from the right protocol at the
	// wrong width, and says which it is.
	wrongType := &layers.ARP{
		AddrType: 1, Protocol: layers.EthernetTypeIPv6, HwAddressSize: 6, ProtAddressSize: 16,
		Operation: 1, SourceHwAddress: arpMAC, SourceProtAddress: make([]byte, 16),
		DstHwAddress: arpZeroMAC, DstProtAddress: make([]byte, 16),
	}
	if got := arpOperation(wrongType, false); !strings.Contains(got, "<wrong proto type>") {
		t.Errorf("wrong protocol = %q", got)
	}
	wrongLen := &layers.ARP{
		AddrType: 1, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 6,
		Operation: 1, SourceHwAddress: arpMAC, SourceProtAddress: make([]byte, 6),
		DstHwAddress: arpZeroMAC, DstProtAddress: make([]byte, 6),
	}
	if got := arpOperation(wrongLen, false); !strings.Contains(got, "<wrong len>") {
		t.Errorf("wrong protocol width = %q", got)
	}
}

func TestARPTypeNames(t *testing.T) {
	hardware := map[layers.LinkType]string{
		1: "Ethernet", 6: "TokenRing", 7: "ArcNet", 15: "FrameRelay",
		23: "Strip", 24: "IEEE 1394", 99: "Unknown Hardware (99)",
	}
	for value, want := range hardware {
		if got := arpHardwareName(value); got != want {
			t.Errorf("arpHardwareName(%d) = %q, want %q", value, got, want)
		}
	}
	protocol := map[layers.EthernetType]string{
		layers.EthernetTypeIPv4: "IPv4", layers.EthernetTypeIPv6: "IPv6",
		layers.EthernetTypeARP: "ARP", 0x8035: "Reverse ARP",
		0x1234: "Unknown Protocol (0x1234)",
	}
	for value, want := range protocol {
		if got := arpProtocolName(value); got != want {
			t.Errorf("arpProtocolName(0x%04x) = %q, want %q", uint16(value), got, want)
		}
	}
}
