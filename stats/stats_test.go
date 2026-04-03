package stats

import (
	"net"
	"strings"
	"tcpdump_go/display"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTCPPkt(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack, Window: 65535}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("hello")))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func buildTCPPktFlags(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack, fin, rst bool) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack, FIN: fin, RST: rst, Window: 65535}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("x")))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func buildUDPPkt(srcIP, dstIP string, srcPort, dstPort uint16) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	_ = udp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte{0}))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func buildARPPkt(srcIP, dstIP string) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	hw := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest, SourceHwAddress: hw, SourceProtAddress: net.ParseIP(srcIP).To4(), DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: net.ParseIP(dstIP).To4()}
	eth := &layers.Ethernet{SrcMAC: hw, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	_ = gopacket.SerializeLayers(buf, opts, eth, arp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func TestNewStats(t *testing.T) {
	s := NewStats()
	if s == nil {
		t.Fatal("nil")
	}
	if s.Total != 0 || s.Bytes != 0 {
		t.Error("not zero")
	}
	if s.SrcIPCount == nil || s.DstPortCount == nil {
		t.Error("maps nil")
	}
}

func TestUpdate_TCP(t *testing.T) {
	s := NewStats()
	s.Update(buildTCPPkt("192.168.1.1", "10.0.0.1", 12345, 80, true, false))
	if s.Total != 1 {
		t.Errorf("Total = %d", s.Total)
	}
	if s.IPv4 != 1 {
		t.Errorf("IPv4 = %d", s.IPv4)
	}
	if s.TCP != 1 {
		t.Errorf("TCP = %d", s.TCP)
	}
	if s.TcpSYN != 1 {
		t.Errorf("TcpSYN = %d", s.TcpSYN)
	}
	if s.Bytes == 0 {
		t.Error("Bytes = 0")
	}
	if cnt := s.SrcIPCount["192.168.1.1"]; cnt != 1 {
		t.Errorf("SrcIPCount = %d", cnt)
	}
	if cnt := s.DstPortCount["80"]; cnt != 1 {
		t.Errorf("DstPortCount = %d", cnt)
	}
}

func TestUpdate_UDP(t *testing.T) {
	s := NewStats()
	s.Update(buildUDPPkt("10.0.0.1", "10.0.0.2", 54321, 53))
	if s.UDP != 1 {
		t.Errorf("UDP = %d", s.UDP)
	}
	if s.DstPortCount["53"] != 1 {
		t.Error("no port 53")
	}
}

func TestUpdate_ARP(t *testing.T) {
	s := NewStats()
	s.Update(buildARPPkt("10.0.0.1", "10.0.0.2"))
	if s.ARP != 1 {
		t.Errorf("ARP = %d", s.ARP)
	}
}

func TestUpdate_SizeMinMax(t *testing.T) {
	s := NewStats()
	s.Update(buildTCPPkt("1.1.1.1", "2.2.2.2", 1, 2, false, true))
	s.Update(buildUDPPkt("1.1.1.1", "2.2.2.2", 3, 4))
	if s.MinSize == 0 {
		t.Error("MinSize = 0")
	}
	if s.MaxSize < s.MinSize {
		t.Errorf("MaxSize (%d) < MinSize (%d)", s.MaxSize, s.MinSize)
	}
	if s.SumSize != s.Bytes {
		t.Errorf("SumSize (%d) != Bytes (%d)", s.SumSize, s.Bytes)
	}
}

func TestUpdate_TCPFlags(t *testing.T) {
	s := NewStats()
	s.Update(buildTCPPktFlags("1.1.1.1", "2.2.2.2", 1, 2, true, false, false, false))
	s.Update(buildTCPPktFlags("1.1.1.1", "2.2.2.2", 1, 2, false, true, true, false))
	s.Update(buildTCPPktFlags("1.1.1.1", "2.2.2.2", 1, 2, false, false, false, true))
	if s.TcpSYN != 1 {
		t.Errorf("TcpSYN = %d", s.TcpSYN)
	}
	if s.TcpFIN != 1 {
		t.Errorf("TcpFIN = %d", s.TcpFIN)
	}
	if s.TcpRST != 1 {
		t.Errorf("TcpRST = %d", s.TcpRST)
	}
}

func TestUpdate_Timestamps(t *testing.T) {
	s := NewStats()
	pkt1 := buildTCPPkt("1.1.1.1", "2.2.2.2", 1, 2, false, true)
	pkt1.Metadata().Timestamp = time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	s.Update(pkt1)
	pkt2 := buildTCPPkt("1.1.1.1", "2.2.2.2", 1, 2, false, true)
	pkt2.Metadata().Timestamp = time.Date(2024, 1, 1, 10, 0, 5, 0, time.UTC)
	s.Update(pkt2)
	if !s.FirstPkt.Equal(time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("FirstPkt = %v", s.FirstPkt)
	}
	if !s.LastPkt.Equal(time.Date(2024, 1, 1, 10, 0, 5, 0, time.UTC)) {
		t.Errorf("LastPkt = %v", s.LastPkt)
	}
}

func TestUpdate_MultipleSrcIPs(t *testing.T) {
	s := NewStats()
	for i := 0; i < 5; i++ {
		s.Update(buildTCPPkt("10.0.0.1", "10.0.0.2", 1000, 80, false, true))
	}
	for i := 0; i < 3; i++ {
		s.Update(buildTCPPkt("10.0.0.99", "10.0.0.2", 2000, 80, false, true))
	}
	if s.SrcIPCount["10.0.0.1"] != 5 {
		t.Errorf("10.0.0.1 = %d", s.SrcIPCount["10.0.0.1"])
	}
	if s.SrcIPCount["10.0.0.99"] != 3 {
		t.Errorf("10.0.0.99 = %d", s.SrcIPCount["10.0.0.99"])
	}
}

func TestPct(t *testing.T) {
	tests := []struct {
		part, total uint64
		want        string
	}{
		{0, 0, "\u2014"},
		{1, 2, "50.0%"},
		{1, 4, "25.0%"},
		{3, 3, "100.0%"},
		{0, 10, "0.0%"},
	}
	for _, tc := range tests {
		got := Pct(tc.part, tc.total)
		if got != tc.want {
			t.Errorf("Pct(%d, %d) = %q, want %q", tc.part, tc.total, got, tc.want)
		}
	}
}

func TestTopN(t *testing.T) {
	m := map[string]uint64{"a": 10, "b": 5, "c": 20, "d": 1}
	top := TopN(m, 2)
	if len(top) != 2 {
		t.Fatalf("len = %d", len(top))
	}
	if !strings.Contains(top[0], "c") || !strings.Contains(top[0], "20") {
		t.Errorf("top[0] = %q", top[0])
	}
	if !strings.Contains(top[1], "a") || !strings.Contains(top[1], "10") {
		t.Errorf("top[1] = %q", top[1])
	}
}

func TestTopN_Empty(t *testing.T) {
	top := TopN(map[string]uint64{}, 5)
	if len(top) != 0 {
		t.Errorf("len = %d", len(top))
	}
}

func TestTopN_LargerN(t *testing.T) {
	m := map[string]uint64{"x": 1}
	top := TopN(m, 100)
	if len(top) != 1 {
		t.Errorf("len = %d", len(top))
	}
}

func TestPrint_Smoke(t *testing.T) {
	s := NewStats()
	s.Update(buildTCPPkt("10.0.0.1", "10.0.0.2", 1234, 80, true, false))
	s.Update(buildUDPPkt("10.0.0.1", "10.0.0.2", 5000, 53))
	s.Update(buildARPPkt("10.0.0.3", "10.0.0.4"))
	buf, restore := display.CaptureOut()
	defer restore()
	s.Print()
	display.FlushOut()
	out := buf.String()
	for _, want := range []string{"Session", "TCP", "UDP", "ARP", "Packets"} {
		if !strings.Contains(out, want) {
			t.Errorf("Print(): brak %q", want)
		}
	}
}

func TestPrint_WithDropped(t *testing.T) {
	s := NewStats()
	s.Update(buildTCPPkt("1.1.1.1", "2.2.2.2", 80, 80, false, true))
	s.Dropped.Store(42)
	buf, restore := display.CaptureOut()
	defer restore()
	s.Print()
	display.FlushOut()
	if !strings.Contains(buf.String(), "42") {
		t.Error("should show Dropped=42")
	}
}
