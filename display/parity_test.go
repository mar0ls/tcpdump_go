package display

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestFormatTSHandlesNegativeAndLocalTime(t *testing.T) {
	oldColor := UseColor
	oldZone := displayZone
	UseColor = false
	defer func() {
		UseColor = oldColor
		displayZone = oldZone
	}()

	if got := FormatTS(time.Unix(0, -1000), time.Time{}, TSUnix); got != "-0.000001" {
		t.Fatalf("pre-epoch Unix timestamp = %q", got)
	}
	if got := FormatTS(time.Unix(9, 500_000_000), time.Unix(10, 0), TSDelta); got != "-00:00:00.500000" {
		t.Fatalf("negative delta = %q", got)
	}
	displayZone = time.FixedZone("test+2", 2*60*60)
	if got := FormatTS(time.Unix(0, 0).UTC(), time.Time{}, TSDateTime); got != "1970-01-01 02:00:00.000000" {
		t.Fatalf("local timestamp = %q", got)
	}
}

// tcpdump marks any question count other than one with "[Nq]". The exact
// spellings below were taken from tcpdump 4.99.1 on the same fixtures: a query
// separates its questions with a space, a response repeats the "q:" tag and
// separates with a comma, and a response that does not echo the section closes
// the marker with a comma instead.
func TestDNSQuestionCountMatchesTcpdump(t *testing.T) {
	question := func(name string) layers.DNSQuestion {
		return layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	}
	answer := layers.DNSResourceRecord{
		Name: []byte("example.com"), Type: layers.DNSTypeA,
		Class: layers.DNSClassIN, TTL: 300, IP: net.IP{1, 2, 3, 4},
	}
	cases := []struct {
		name      string
		dns       *layers.DNS
		length    int
		verbosity int
		want      string
	}{
		{
			name:   "query with the usual single question",
			dns:    &layers.DNS{ID: 100, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{question("example.com")}},
			length: 29,
			want:   "100+ A? example.com. (29)",
		},
		{
			name:   "query with no question section",
			dns:    &layers.DNS{ID: 101, RD: true},
			length: 12,
			want:   "101+ [0q] (12)",
		},
		{
			name:   "query with two questions is space separated",
			dns:    &layers.DNS{ID: 102, RD: true, QDCount: 2, Questions: []layers.DNSQuestion{question("a.example.com"), question("b.example.com")}},
			length: 50,
			want:   "102+ [2q] A? a.example.com. A? b.example.com. (50)",
		},
		{
			name: "response without the echoed section closes the marker with a comma",
			dns: &layers.DNS{
				ID: 104, QR: true, RD: true, RA: true, QDCount: 2, ANCount: 1,
				Questions: []layers.DNSQuestion{question("a.example.com"), question("b.example.com")},
				Answers:   []layers.DNSResourceRecord{answer},
			},
			length: 77,
			want:   "104 [2q], 1/0/0 A 1.2.3.4 (77)",
		},
		{
			name: "response echoing the section repeats the q: tag",
			dns: &layers.DNS{
				ID: 104, QR: true, RD: true, RA: true, QDCount: 2, ANCount: 1,
				Questions: []layers.DNSQuestion{question("a.example.com"), question("b.example.com")},
				Answers:   []layers.DNSResourceRecord{answer},
			},
			length:    77,
			verbosity: 2,
			want:      "104 [2q] q: A? a.example.com., q: A? b.example.com. 1/0/0 example.com. A 1.2.3.4 (77)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsSummary(tc.dns, tc.length, tc.verbosity); got != tc.want {
				t.Fatalf("dnsSummary =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

func TestTruncatedTCPPrintsMarkerWithoutFabricatedFields(t *testing.T) {
	raw := buildTCPPacket("192.0.2.1", "198.51.100.2", 12345, 80, false, true)
	raw = raw[:14+20+10]
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{CaptureLength: len(raw), Length: 60}
	packet.Metadata().Truncated = true

	buffer, restore := CaptureOut()
	defer restore()
	ConfigureRenderer(RenderOptions{NumericPorts: true})
	defer ResetRenderer()
	if err := PrintNormal(1, packet, "", true); err != nil {
		t.Fatal(err)
	}
	if err := FlushOut(); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !strings.Contains(output, "192.0.2.1.12345 > 198.51.100.2.80: [|tcp]") {
		t.Fatalf("truncated TCP output = %q", output)
	}
	if strings.Contains(output, "seq 0") || strings.Contains(output, "ack 0") {
		t.Fatalf("fabricated TCP fields in %q", output)
	}
}

func TestTruncatedEthernetStillPrintsALine(t *testing.T) {
	packet := gopacket.NewPacket(make([]byte, 10), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Truncated = true
	buffer, restore := CaptureOut()
	defer restore()
	if err := PrintNormal(1, packet, "", true); err != nil {
		t.Fatal(err)
	}
	_ = FlushOut()
	if !strings.Contains(buffer.String(), "[|ether]") {
		t.Fatalf("truncated Ethernet output = %q", buffer.String())
	}
}

func TestIPv4FragmentOffsetUsesByteUnits(t *testing.T) {
	buffer := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{
		Version:    4,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      net.ParseIP("192.0.2.1").To4(),
		DstIP:      net.ParseIP("198.51.100.2").To4(),
		Flags:      layers.IPv4MoreFragments,
		FragOffset: 1,
	}
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, gopacket.Payload(make([]byte, 8))); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	out, restore := CaptureOut()
	defer restore()
	if err := PrintVerbose(1, packet, "", 1, true); err != nil {
		t.Fatal(err)
	}
	_ = FlushOut()
	if !strings.Contains(out.String(), "offset 8") || strings.Contains(out.String(), "offset 1,") {
		t.Fatalf("fragment output = %q", out.String())
	}
}

func TestICMPUnknownProtocolAndSCTPExposeProtocolData(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want []string
	}{
		{name: "icmp", raw: buildICMPPacket(), want: []string{"ICMP echo request", "id 7", "seq 9", "length 12"}},
		{name: "unknown", raw: buildUnknownProtocolPacket(), want: []string{"ip-proto-253", "length 4"}},
		{name: "sctp", raw: buildSCTPPacket(), want: []string{"5000", "5001", "sctp"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := gopacket.NewPacket(test.raw, layers.LayerTypeEthernet, gopacket.Default)
			out, restore := CaptureOut()
			defer restore()
			ConfigureRenderer(RenderOptions{NumericPorts: true})
			defer ResetRenderer()
			if err := PrintNormal(1, packet, "", true); err != nil {
				t.Fatal(err)
			}
			_ = FlushOut()
			for _, want := range test.want {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q in %q", want, out.String())
				}
			}
		})
	}
}

func TestTCPFlagsMatchTcpdumpNotation(t *testing.T) {
	tcp := &layers.TCP{FIN: true, SYN: true, ACK: true, ECE: true, CWR: true, NS: true}
	if got := TCPFlagsShort(tcp); got != "FS.EWA" {
		t.Fatalf("flags = %q", got)
	}
}

func TestTCPSequenceNumbersFollowTcpdumpConversationState(t *testing.T) {
	ConfigureRenderer(RenderOptions{NumericPorts: true})
	defer ResetRenderer()

	assertNumbers := func(label string, tcp *layers.TCP, src, dst string, wantSeq, wantAck uint32) {
		t.Helper()
		seq, ack := tcpSequenceNumbers(src, dst, tcp)
		if seq != wantSeq || ack != wantAck {
			t.Fatalf("%s sequence = %d, ack = %d; want %d/%d", label, seq, ack, wantSeq, wantAck)
		}
	}

	assertNumbers("initial SYN", &layers.TCP{
		SrcPort: 12345, DstPort: 80, SYN: true, Seq: 100,
	}, "192.0.2.1", "198.51.100.2", 100, 0)
	assertNumbers("SYN-ACK establishes bases", &layers.TCP{
		SrcPort: 80, DstPort: 12345, SYN: true, ACK: true, Seq: 900, Ack: 101,
	}, "198.51.100.2", "192.0.2.1", 900, 101)
	assertNumbers("client ACK is relative", &layers.TCP{
		SrcPort: 12345, DstPort: 80, ACK: true, Seq: 101, Ack: 901,
	}, "192.0.2.1", "198.51.100.2", 1, 1)
	assertNumbers("server ACK is relative", &layers.TCP{
		SrcPort: 80, DstPort: 12345, ACK: true, Seq: 901, Ack: 102,
	}, "198.51.100.2", "192.0.2.1", 1, 2)

	ConfigureRenderer(RenderOptions{AbsoluteSequenceNumbers: true, NumericPorts: true})
	assertNumbers("-S stays absolute", &layers.TCP{
		SrcPort: 12345, DstPort: 80, ACK: true, Seq: 101, Ack: 901,
	}, "192.0.2.1", "198.51.100.2", 101, 901)
}

func TestIPv6ExtensionHeaderIsNotCountedAsTCPPayload(t *testing.T) {
	buffer := gopacket.NewSerializeBuffer()
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolIPv6HopByHop,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolTCP
	option := &layers.IPv6HopByHopOption{}
	option.OptionType = 1
	option.OptionData = []byte{0, 0, 0, 0}
	hop.Options = append(hop.Options, option)
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 443, ACK: true, Seq: 10, Ack: 20, Window: 1024}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	ethernet := &layers.Ethernet{
		SrcMAC:       make(net.HardwareAddr, 6),
		DstMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
		EthernetType: layers.EthernetTypeIPv6,
	}
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet, ip, hop, tcp, gopacket.Payload([]byte{1, 2, 3, 4}),
	); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	out, restore := CaptureOut()
	defer restore()
	ConfigureRenderer(RenderOptions{NumericPorts: true})
	defer ResetRenderer()
	if err := PrintNormal(1, packet, "", true); err != nil {
		t.Fatal(err)
	}
	if err := FlushOut(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "length 4") || strings.Contains(out.String(), "length 12") {
		t.Fatalf("IPv6 extension output = %q", out.String())
	}
}

func buildICMPPacket() []byte {
	buffer := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("198.51.100.2").To4()}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 7, Seq: 9}
	ethernet := &layers.Ethernet{SrcMAC: make(net.HardwareAddr, 6), DstMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, icmp, gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func buildUnknownProtocolPacket() []byte {
	buffer := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocol(253), SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("198.51.100.2").To4()}
	ethernet := &layers.Ethernet{SrcMAC: make(net.HardwareAddr, 6), DstMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func buildSCTPPacket() []byte {
	buffer := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolSCTP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("198.51.100.2").To4()}
	sctp := &layers.SCTP{SrcPort: 5000, DstPort: 5001}
	ethernet := &layers.Ethernet{SrcMAC: make(net.HardwareAddr, 6), DstMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, sctp); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}
