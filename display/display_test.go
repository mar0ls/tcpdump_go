// Package display — testy jednostkowe.
package display

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// =============================================================================
// Helpery testowe
// =============================================================================

func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack, Window: 65535}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("hello"))); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func buildUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	_ = udp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte{0x00})); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func buildARPPacket(srcIP, dstIP, srcMAC string) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	hw, _ := net.ParseMAC(srcMAC)
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest, SourceHwAddress: hw, SourceProtAddress: net.ParseIP(srcIP).To4(), DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: net.ParseIP(dstIP).To4()}
	eth := &layers.Ethernet{SrcMAC: hw, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func decode(raw []byte) gopacket.Packet {
	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
}

// =============================================================================
// Colorize
// =============================================================================

func TestColorize_Off(t *testing.T) {
	old := UseColor
	UseColor = false
	defer func() { UseColor = old }()
	if got := Colorize("test", ColorRed); got != "test" {
		t.Errorf("want %q, got %q", "test", got)
	}
}

func TestColorize_On(t *testing.T) {
	old := UseColor
	UseColor = true
	defer func() { UseColor = old }()
	got := Colorize("test", ColorGreen)
	if !strings.HasPrefix(got, ColorGreen) || !strings.HasSuffix(got, ColorReset) {
		t.Errorf("ANSI codes missing: %q", got)
	}
}

// =============================================================================
// AppendOffset
// =============================================================================

func TestAppendOffset_Values(t *testing.T) {
	for _, tc := range []struct {
		off  int
		want string
	}{
		{0, "0000"}, {16, "0010"}, {255, "00ff"}, {4096, "1000"}, {65535, "ffff"},
	} {
		got := string(AppendOffset(nil, tc.off))
		if got != tc.want {
			t.Errorf("AppendOffset(%d) = %q, want %q", tc.off, got, tc.want)
		}
	}
}

// =============================================================================
// PrintHex / PrintHexASCII
// =============================================================================

func TestPrintHex_Output(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	data := []byte{0x00, 0x01, 0x02, 0xff}
	PrintHex(data)
	FlushOut()
	out := buf.String()
	if !strings.Contains(out, "0000") {
		t.Errorf("offset 0000 missing: %q", out)
	}
	if !strings.Contains(out, "ff") {
		t.Errorf("'ff' missing: %q", out)
	}
}

func TestPrintHexASCII_ContainsPipe(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	PrintHexASCII([]byte("Hello!"))
	FlushOut()
	if !strings.Contains(buf.String(), "|") {
		t.Errorf("separator '|' missing: %q", buf.String())
	}
}

func TestPrintHex_Empty(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	PrintHex([]byte{})
	FlushOut()
	if buf.Len() != 0 {
		t.Errorf("empty data should not produce output: %q", buf.String())
	}
}

func TestPrintHexASCII_MultiLine(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 0x40) // @ABCDE...
	}
	PrintHexASCII(data)
	FlushOut()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("32 bytes = 2 rows, got %d", len(lines))
	}
}

// =============================================================================
// PacketPayload
// =============================================================================

func TestPacketPayload_StripsEthernet(t *testing.T) {
	pkt := decode(buildTCPPacket("1.2.3.4", "5.6.7.8", 1234, 80, true, false))
	full := pkt.Data()
	payload := PacketPayload(pkt)
	if diff := len(full) - len(payload); diff != 14 {
		t.Errorf("length diff = %d, want 14 (Ethernet)", diff)
	}
}

// =============================================================================
// ExtractPorts / ExtractTransportInfo
// =============================================================================

func TestExtractPorts_TCP(t *testing.T) {
	pkt := decode(buildTCPPacket("1.1.1.1", "2.2.2.2", 12345, 80, true, false))
	s, d := ExtractPorts(pkt.TransportLayer())
	if s != "12345" || d != "80" {
		t.Errorf("sport=%q dport=%q", s, d)
	}
}

func TestExtractPorts_UDP(t *testing.T) {
	pkt := decode(buildUDPPacket("1.1.1.1", "2.2.2.2", 54321, 53))
	s, d := ExtractPorts(pkt.TransportLayer())
	if s != "54321" || d != "53" {
		t.Errorf("sport=%q dport=%q", s, d)
	}
}

func TestExtractTransportInfo_TCP(t *testing.T) {
	pkt := decode(buildTCPPacket("1.1.1.1", "2.2.2.2", 1234, 443, true, false))
	proto, sport, dport := ExtractTransportInfo(pkt)
	if proto != "TCP" {
		t.Errorf("proto = %q, want TCP", proto)
	}
	if sport != "1234" || dport != "443" {
		t.Errorf("sport=%q dport=%q", sport, dport)
	}
}

func TestExtractTransportInfo_ARP(t *testing.T) {
	pkt := decode(buildARPPacket("1.1.1.1", "2.2.2.2", "aa:bb:cc:dd:ee:ff"))
	proto, sport, dport := ExtractTransportInfo(pkt)
	if proto != "other" || sport != "" || dport != "" {
		t.Errorf("ARP: proto=%q sport=%q dport=%q", proto, sport, dport)
	}
}

// =============================================================================
// TcpFlagsShort
// =============================================================================

func TestTcpFlagsShort_All(t *testing.T) {
	for _, tc := range []struct {
		name string
		tcp  layers.TCP
		want string
	}{
		{"SYN", layers.TCP{SYN: true}, "S"},
		{"SA", layers.TCP{SYN: true, ACK: true}, "SA"},
		{"AP", layers.TCP{ACK: true, PSH: true}, "AP"},
		{"AF", layers.TCP{ACK: true, FIN: true}, "AF"},
		{"R", layers.TCP{RST: true}, "R"},
		{"none", layers.TCP{}, "."},
		{"all", layers.TCP{SYN: true, ACK: true, FIN: true, RST: true, PSH: true, URG: true}, "SAFRPU"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tcp := tc.tcp
			if got := TcpFlagsShort(&tcp); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// =============================================================================
// TcpOptionsStr
// =============================================================================

func TestTcpOptionsStr_Empty(t *testing.T) {
	tcp := &layers.TCP{}
	if got := TcpOptionsStr(tcp); got != "" {
		t.Errorf("want empty, got %q", got)
	}
}

func TestTcpOptionsStr_NOP(t *testing.T) {
	tcp := &layers.TCP{Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindNop}}}
	if got := TcpOptionsStr(tcp); got != "nop" {
		t.Errorf("want 'nop', got %q", got)
	}
}

func TestTcpOptionsStr_MSS(t *testing.T) {
	tcp := &layers.TCP{Options: []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xB4}}, // 1460
	}}
	got := TcpOptionsStr(tcp)
	if !strings.Contains(got, "mss 1460") {
		t.Errorf("want 'mss 1460', got %q", got)
	}
}

// =============================================================================
// FormatTS
// =============================================================================

func TestFormatTS_Modes(t *testing.T) {
	ts := time.Date(2024, 6, 15, 12, 30, 45, 123456000, time.UTC)
	prev := time.Date(2024, 6, 15, 12, 30, 44, 0, time.UTC)
	for _, tc := range []struct {
		mode, contains string
	}{
		{"default", "12:30:45.123456"},
		{"t", ""},
		{"tt", "."},
		{"ttt", "1.123456"},
		{"tttt", "2024-06-15 12:30:45.123456"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			got := FormatTS(ts, prev, tc.mode)
			if tc.mode == "t" && got != "" {
				t.Errorf("mode=t: want empty, got %q", got)
				return
			}
			if tc.contains != "" && !strings.Contains(got, tc.contains) {
				t.Errorf("mode=%s: want %q in %q", tc.mode, tc.contains, got)
			}
		})
	}
}

func TestFormatTS_TTT_ZeroPrev(t *testing.T) {
	ts := time.Unix(1000, 0)
	got := FormatTS(ts, time.Time{}, "ttt")
	if !strings.Contains(got, "0.000000") {
		t.Errorf("want 0.000000, got %q", got)
	}
}

// =============================================================================
// IpLayerName
// =============================================================================

func TestIpLayerName(t *testing.T) {
	pkt4 := decode(buildTCPPacket("1.2.3.4", "5.6.7.8", 80, 80, false, true))
	if name := IpLayerName(pkt4.NetworkLayer()); name != "IP" {
		t.Errorf("IPv4: got %q, want IP", name)
	}
}

// =============================================================================
// ResolveIP / ClearDNSCache
// =============================================================================

func TestResolveIP_CacheConsistency(t *testing.T) {
	ClearDNSCache("240.0.0.1")
	r1 := ResolveIP("240.0.0.1")
	r2 := ResolveIP("240.0.0.1")
	if r1 != r2 {
		t.Errorf("inconsistent cache: %q vs %q", r1, r2)
	}
}

// =============================================================================
// CaptureOut
// =============================================================================

func TestCaptureOut_Redirects(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	Outf("hello %d", 42)
	FlushOut()
	if !strings.Contains(buf.String(), "hello 42") {
		t.Errorf("CaptureOut did not capture output: %q", buf.String())
	}
}

// =============================================================================
// PrintNormal / PrintVerbose — integracyjne
// =============================================================================

func TestPrintNormal_TCP_Output(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	pkt := decode(buildTCPPacket("192.168.1.1", "8.8.8.8", 12345, 80, true, false))
	PrintNormal(1, pkt, "10:00:00.000000", true)
	FlushOut()
	out := buf.String()
	if !strings.Contains(out, "192.168.1.1") || !strings.Contains(out, "12345") || !strings.Contains(out, "80") {
		t.Errorf("brak wymaganych danych: %q", out)
	}
}

func TestPrintNormal_ARP_Output(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	pkt := decode(buildARPPacket("192.168.1.1", "192.168.1.2", "aa:bb:cc:dd:ee:ff"))
	PrintNormal(1, pkt, "10:00:00.000000", true)
	FlushOut()
	out := buf.String()
	if !strings.Contains(out, "ARP") || !strings.Contains(out, "Request") {
		t.Errorf("ARP output: %q", out)
	}
}

func TestPrintVerbose_TCP_ShowsIPMeta(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	pkt := decode(buildTCPPacket("10.0.0.1", "10.0.0.2", 1234, 443, true, false))
	PrintVerbose(1, pkt, "10:00:00.000000", true)
	FlushOut()
	out := buf.String()
	for _, want := range []string{"tos", "ttl", "Flags", "seq"} {
		if !strings.Contains(out, want) {
			t.Errorf("brak %q w verbose: %q", want, out)
		}
	}
}

func TestPrintVerbose_UDP_ShowsProto(t *testing.T) {
	buf, restore := CaptureOut()
	defer restore()
	pkt := decode(buildUDPPacket("10.0.0.1", "10.0.0.2", 12345, 53))
	PrintVerbose(1, pkt, "10:00:00.000000", true)
	FlushOut()
	out := buf.String()
	if !strings.Contains(out, "proto UDP") {
		t.Errorf("brak 'proto UDP': %q", out)
	}
}

func TestPrintPacket_AllViewModes(t *testing.T) {
	pkt := decode(buildTCPPacket("1.2.3.4", "5.6.7.8", 1000, 80, true, false))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		mode, want string
	}{
		{"normal", "1.2.3.4"},
		{"verbose", "tos"},
		{"hex", "0000"},
		{"hexascii", "|"},
		{"hex_link", "0000"},
		{"hexascii_link", "|"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			buf, restore := CaptureOut()
			defer restore()
			PrintPacket(1, pkt, ts, time.Time{}, tc.mode, "default", false, true)
			FlushOut()
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("mode=%q: brak %q w %q", tc.mode, tc.want, buf.String())
			}
		})
	}
}
