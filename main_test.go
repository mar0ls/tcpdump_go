package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"tcpdump_go/display"
	"tcpdump_go/rotation"
	"tcpdump_go/stats"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestMain creates test fixtures and builds the test binary before running the entire suite.
func TestMain(m *testing.M) {
	if err := os.MkdirAll("testdata", 0o750); err != nil { //#nosec G301 -- test directory
		panic(err)
	}
	createTestPcap("testdata/test.pcap")

	// Build the binary once — used by comparison tests (tcpdump_go vs tcpdump).
	dir, err := os.MkdirTemp("", "tcpdump_go_bin_")
	if err == nil {
		compareBinaryDir = dir
		compareBinaryPath = filepath.Join(dir, "tcpdump_go")
		cmd := exec.Command("go", "build", "-o", compareBinaryPath, ".") //#nosec G204
		if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
			fmt.Fprintf(os.Stderr, "WARN: could not build comparison binary: %v\n%s\n", buildErr, out)
			compareBinaryPath = ""
		}
	}

	code := m.Run()
	if compareBinaryDir != "" {
		_ = os.RemoveAll(compareBinaryDir)
	}
	os.Exit(code)
}

// createTestPcap writes a minimal pcap file with one TCP and one UDP packet.
func createTestPcap(path string) {
	f, err := os.Create(path) //#nosec G304 -- fixed test path
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}

	ts := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, pkt := range [][]byte{
		buildTCPPacket("192.168.1.1", "8.8.8.8", 12345, 80, true, false),
		buildUDPPacket("10.0.0.1", "1.1.1.1", 54321, 53),
	} {
		ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}
		if err := w.WritePacket(ci, pkt); err != nil {
			panic(err)
		}
		ts = ts.Add(time.Millisecond)
	}
}

// Helpers — raw packet construction

func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Window:  65535,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("hello"))); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func buildUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte{0x00})); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func decodePacket(raw []byte) gopacket.Packet {
	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
}

func buildARPPacket(srcIP, dstIP, srcMAC string) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}

	hw, _ := net.ParseMAC(srcMAC)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   hw,
		SourceProtAddress: net.ParseIP(srcIP).To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(dstIP).To4(),
	}
	eth := &layers.Ethernet{
		SrcMAC:       hw,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// openPcapFile

func TestOpenPcapFile_Pcap(t *testing.T) {
	f, reader := openPcapFile("testdata/test.pcap")
	defer func() { _ = f.Close() }()

	if reader == nil {
		t.Fatal("reader must not be nil")
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("LinkType = %v, want Ethernet", reader.LinkType())
	}
}

func TestOpenPcapFile_ReadPackets(t *testing.T) {
	f, reader := openPcapFile("testdata/test.pcap")
	defer func() { _ = f.Close() }()

	src := gopacket.NewPacketSource(reader, reader.LinkType())
	var count int
	for range src.Packets() {
		count++
	}
	if count != 2 {
		t.Errorf("packet count = %d, want 2", count)
	}
}

// writeCSV

func TestWriteCSV(t *testing.T) {
	path := t.TempDir() + "/flows.csv"
	flowMap := map[flowKey]int{
		{Src: "1.1.1.1", Dst: "2.2.2.2", Sport: "1234", Dport: "80", Proto: "TCP"}: 5,
		{Src: "3.3.3.3", Dst: "4.4.4.4", Sport: "9999", Dport: "53", Proto: "UDP"}: 2,
	}

	_, restore := display.CaptureOut()
	defer restore()
	writeCSV(path, flowMap)

	f, err := os.Open(path) //#nosec G304 -- path from t.TempDir()
	if err != nil {
		t.Fatalf("CSV file missing: %v", err)
	}
	defer func() { _ = f.Close() }()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error: %v", err)
	}

	if len(records) < 2 {
		t.Fatalf("CSV has %d rows, want >= 2 (header + data)", len(records))
	}

	header := strings.Join(records[0], ",")
	wantHeader := "src_ip,dst_ip,src_port,dst_port,proto,count"
	if header != wantHeader {
		t.Errorf("header = %q, want %q", header, wantHeader)
	}
	if len(records) != 3 {
		t.Errorf("row count = %d, want 3", len(records))
	}
}

// runReadPcap — integration tests

func TestRunReadPcap_Normal(_ *testing.T) {
	_, restore := display.CaptureOut()
	defer restore()
	runReadPcap("testdata/test.pcap", "", "", "normal", "default", false, true, false, false, "", 0)
}

func TestRunReadPcap_WithStats(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	runReadPcap("testdata/test.pcap", "", "", "normal", "default", false, true, true, false, "", 0)
	display.FlushOut()

	output := buf.String()
	if !strings.Contains(output, "Session summary") {
		t.Errorf("stats section not found in output")
	}
	if !strings.Contains(output, "TCP") {
		t.Errorf("TCP missing from stats output")
	}
}

func TestRunReadPcap_WithCount(t *testing.T) {
	s := stats.NewStats()
	f, reader := openPcapFile("testdata/test.pcap")
	defer func() { _ = f.Close() }()
	src := gopacket.NewPacketSource(reader, reader.LinkType())
	var n uint64
	for pkt := range src.Packets() {
		n++
		s.Update(pkt)
		if n >= 1 {
			break
		}
	}
	if s.Total != 1 {
		t.Errorf("with count=1 got %d packets, want 1", s.Total)
	}
}

func TestRunReadPcap_AllViewModes(t *testing.T) {
	modes := []string{"normal", "verbose", "hex", "hexascii", "hex_link", "hexascii_link"}
	for _, mode := range modes {
		t.Run(mode, func(_ *testing.T) {
			_, restore := display.CaptureOut()
			defer restore()
			runReadPcap("testdata/test.pcap", "", "", mode, "default", false, true, false, false, "", 0)
		})
	}
}

func TestRunReadPcap_WithCSV(t *testing.T) {
	csvPath := t.TempDir() + "/out.csv"
	_, restore := display.CaptureOut()
	defer restore()

	runReadPcap("testdata/test.pcap", "", "", "normal", "default", false, true, false, false, csvPath, 0)

	if _, err := os.Stat(csvPath); err != nil {
		t.Errorf("CSV file not created: %v", err)
	}
}

func TestRunReadPcap_DisableDNS(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	runReadPcap("testdata/test.pcap", "", "", "normal", "default", true, true, false, false, "", 0)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "192.168.1.1") && !strings.Contains(out, "10.0.0.1") {
		t.Errorf("-n: expected raw IP in output: %q", out)
	}
}

func TestRunReadPcap_Quiet(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	runReadPcap("testdata/test.pcap", "", "", "normal", "default", false, true, false, true, "", 0)
	display.FlushOut()

	if buf.Len() != 0 {
		t.Errorf("-q: expected no output, got: %q", buf.String())
	}
}

func TestRunReadPcap_Count(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	runReadPcap("testdata/test.pcap", "", "", "normal", "default", false, true, false, false, "", 1)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "#1") {
		t.Errorf("-c 1: missing #1 in output: %q", out)
	}
	if strings.Contains(out, "#2") {
		t.Errorf("-c 1: unexpected #2 in output: %q", out)
	}
}

func TestRunReadPcap_TimestampModes(t *testing.T) {
	tsModes := []struct {
		mode        string
		mustContain string
	}{
		{"default", ":"},
		{"t", "#1"},
		{"tt", "."},
		{"ttt", "."},
		{"tttt", "-"},
	}

	for _, tt := range tsModes {
		t.Run(tt.mode, func(t *testing.T) {
			buf, restore := display.CaptureOut()
			defer restore()
			runReadPcap("testdata/test.pcap", "", "", "normal", tt.mode, false, true, false, false, "", 0)
			display.FlushOut()
			got := buf.String()
			if !strings.Contains(got, tt.mustContain) {
				t.Errorf("tsMode=%q: want %q in %q", tt.mode, tt.mustContain, got)
			}
		})
	}
}

// expandArgs — POSIX-style flag combining

func TestExpandArgs_Combined(t *testing.T) {
	tests := []struct {
		input []string
		want  []string
	}{
		{[]string{"-nXX"}, []string{"-n", "-XX"}},
		{[]string{"-nx"}, []string{"-n", "-x"}},
		{[]string{"-nX"}, []string{"-n", "-X"}},
		{[]string{"-nv"}, []string{"-n", "-v"}},
		{[]string{"-nvXX"}, []string{"-n", "-v", "-XX"}},
		{[]string{"-ntttt"}, []string{"-n", "-tttt"}},
		{[]string{"-nttt"}, []string{"-n", "-ttt"}},
		{[]string{"-ntt"}, []string{"-n", "-tt"}},
		{[]string{"-nt"}, []string{"-n", "-t"}},
		{[]string{"-n", "-XX"}, []string{"-n", "-XX"}},
		{[]string{"-r", "file.pcap"}, []string{"-r", "file.pcap"}},
		{[]string{"tcp port 80"}, []string{"tcp port 80"}},
		{[]string{"-XX"}, []string{"-XX"}},
	}
	for _, tt := range tests {
		got := expandArgs(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("expandArgs(%v) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("expandArgs(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// stats package integration tests (called from main)

func TestStatsUpdate_TCP(t *testing.T) {
	s := stats.NewStats()
	pkt := decodePacket(buildTCPPacket("1.2.3.4", "5.6.7.8", 1234, 80, true, false))
	s.Update(pkt)

	if s.Total != 1 {
		t.Errorf("Total = %d, want 1", s.Total)
	}
	if s.TCP != 1 {
		t.Errorf("TCP = %d, want 1", s.TCP)
	}
}

func TestStatsUpdate_UDP(t *testing.T) {
	s := stats.NewStats()
	pkt := decodePacket(buildUDPPacket("1.2.3.4", "5.6.7.8", 1234, 53))
	s.Update(pkt)
	if s.UDP != 1 {
		t.Errorf("UDP = %d, want 1", s.UDP)
	}
}

func TestStatsUpdate_Bytes(t *testing.T) {
	s := stats.NewStats()
	raw := buildTCPPacket("1.2.3.4", "5.6.7.8", 1234, 80, false, true)
	s.Update(decodePacket(raw))
	if s.Bytes != uint64(len(raw)) {
		t.Errorf("Bytes = %d, want %d", s.Bytes, len(raw))
	}
}

func TestStatsUpdate_MultiplePackets(t *testing.T) {
	s := stats.NewStats()
	s.Update(decodePacket(buildTCPPacket("1.1.1.1", "2.2.2.2", 1000, 80, true, false)))
	s.Update(decodePacket(buildTCPPacket("1.1.1.1", "2.2.2.2", 1001, 80, false, true)))
	s.Update(decodePacket(buildUDPPacket("3.3.3.3", "4.4.4.4", 5000, 53)))

	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.TCP != 2 {
		t.Errorf("TCP = %d, want 2", s.TCP)
	}
	if s.UDP != 1 {
		t.Errorf("UDP = %d, want 1", s.UDP)
	}
}

func TestStatsUpdate_SizeMinMax(t *testing.T) {
	s := stats.NewStats()
	small := buildUDPPacket("1.1.1.1", "2.2.2.2", 1111, 53)
	large := buildTCPPacket("1.1.1.1", "2.2.2.2", 2222, 80, true, false)
	s.Update(decodePacket(small))
	s.Update(decodePacket(large))

	if s.MinSize != uint64(len(small)) {
		t.Errorf("MinSize = %d, want %d", s.MinSize, len(small))
	}
	if s.MaxSize != uint64(len(large)) {
		t.Errorf("MaxSize = %d, want %d", s.MaxSize, len(large))
	}
}

func TestStatsUpdate_TCPFlags(t *testing.T) {
	s := stats.NewStats()
	s.Update(decodePacket(buildTCPPacket("1.1.1.1", "2.2.2.2", 1000, 80, true, false)))
	s.Update(decodePacket(buildTCPPacket("1.1.1.1", "2.2.2.2", 1000, 80, false, true)))

	if s.TcpSYN != 1 {
		t.Errorf("TcpSYN = %d, want 1", s.TcpSYN)
	}
}

func TestStatsUpdate_TopSrcIP(t *testing.T) {
	s := stats.NewStats()
	for range 3 {
		s.Update(decodePacket(buildTCPPacket("10.0.0.1", "8.8.8.8", 1234, 80, false, true)))
	}
	s.Update(decodePacket(buildTCPPacket("10.0.0.2", "8.8.8.8", 5678, 80, false, true)))

	if s.SrcIPCount["10.0.0.1"] != 3 {
		t.Errorf("SrcIPCount[10.0.0.1] = %d, want 3", s.SrcIPCount["10.0.0.1"])
	}
	top := stats.TopN(s.SrcIPCount, 1)
	if len(top) == 0 || !strings.Contains(top[0], "10.0.0.1") {
		t.Errorf("top sender should be 10.0.0.1, got: %v", top)
	}
}

// display package tests (called from main)

func TestTcpFlagsShort(t *testing.T) {
	tests := []struct {
		name string
		tcp  layers.TCP
		want string
	}{
		{"SYN", layers.TCP{SYN: true}, "S"},
		{"SYN+ACK", layers.TCP{SYN: true, ACK: true}, "SA"},
		{"PSH+ACK", layers.TCP{PSH: true, ACK: true}, "AP"},
		{"FIN+ACK", layers.TCP{FIN: true, ACK: true}, "AF"},
		{"RST", layers.TCP{RST: true}, "R"},
		{"empty", layers.TCP{}, "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := tt.tcp
			got := display.TcpFlagsShort(&tcp)
			if got != tt.want {
				t.Errorf("TcpFlagsShort: want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestColorize_NoColor(t *testing.T) {
	old := display.UseColor
	display.UseColor = false
	defer func() { display.UseColor = old }()

	got := display.Colorize("hello", display.ColorRed)
	if got != "hello" {
		t.Errorf("no color: want %q, got %q", "hello", got)
	}
}

func TestColorize_WithColor(t *testing.T) {
	old := display.UseColor
	display.UseColor = true
	defer func() { display.UseColor = old }()

	got := display.Colorize("hello", display.ColorRed)
	if !strings.Contains(got, "hello") {
		t.Errorf("result should contain original text, got %q", got)
	}
	if !strings.HasPrefix(got, display.ColorRed) {
		t.Errorf("result should start with color code")
	}
	if !strings.HasSuffix(got, display.ColorReset) {
		t.Errorf("result should end with color reset")
	}
}

func TestAppendOffset(t *testing.T) {
	tests := []struct {
		offset int
		want   string
	}{
		{0, "0000"},
		{16, "0010"},
		{255, "00ff"},
		{4096, "1000"},
		{65535, "ffff"},
	}
	for _, tt := range tests {
		buf := display.AppendOffset(nil, tt.offset)
		got := string(buf)
		if got != tt.want {
			t.Errorf("offset %d: want %q, got %q", tt.offset, tt.want, got)
		}
	}
}

func TestPrintHex_NonemptyData(_ *testing.T) {
	_, restore := display.CaptureOut()
	defer restore()
	data := make([]byte, 48)
	for i := range data {
		data[i] = byte(i)
	}
	display.PrintHex(data)
}

func TestPrintHexASCII_NonemptyData(_ *testing.T) {
	_, restore := display.CaptureOut()
	defer restore()
	data := []byte("Hello, World! \x00\x01\x02")
	display.PrintHexASCII(data)
}

func TestPrintHex_EmptyData(_ *testing.T) {
	_, restore := display.CaptureOut()
	defer restore()
	display.PrintHex([]byte{})
}

func TestExtractPorts_TCP(t *testing.T) {
	pkt := decodePacket(buildTCPPacket("1.1.1.1", "2.2.2.2", 12345, 80, true, false))
	tl := pkt.TransportLayer()
	if tl == nil {
		t.Fatal("transport layer missing")
	}
	sport, dport := display.ExtractPorts(tl)
	if sport != "12345" {
		t.Errorf("sport = %q, want %q", sport, "12345")
	}
	if dport != "80" {
		t.Errorf("dport = %q, want %q", dport, "80")
	}
}

func TestExtractPorts_UDP(t *testing.T) {
	pkt := decodePacket(buildUDPPacket("1.1.1.1", "2.2.2.2", 54321, 53))
	tl := pkt.TransportLayer()
	if tl == nil {
		t.Fatal("transport layer missing")
	}
	sport, dport := display.ExtractPorts(tl)
	if sport != "54321" {
		t.Errorf("sport = %q, want %q", sport, "54321")
	}
	if dport != "53" {
		t.Errorf("dport = %q, want %q", dport, "53")
	}
}

func TestResolveIP_Cache(t *testing.T) {
	display.ClearDNSCache("240.0.0.1")
	r1 := display.ResolveIP("240.0.0.1")
	r2 := display.ResolveIP("240.0.0.1")
	if r1 != r2 {
		t.Errorf("cache returned different results: %q vs %q", r1, r2)
	}
}

func TestResolveIP_Loopback(t *testing.T) {
	display.ClearDNSCache("127.0.0.1")
	result := display.ResolveIP("127.0.0.1")
	if result == "" {
		t.Error("resolveIP must not return empty string")
	}
}

func TestPacketPayload_StripsEthernet(t *testing.T) {
	raw := buildTCPPacket("1.2.3.4", "5.6.7.8", 1234, 80, true, false)
	pkt := decodePacket(raw)

	full := pkt.Data()
	payload := display.PacketPayload(pkt)

	if len(payload) >= len(full) {
		t.Errorf("payload (%d B) should be shorter than full packet (%d B)", len(payload), len(full))
	}
	if len(full)-len(payload) != 14 {
		t.Errorf("length diff = %d, want 14 (Ethernet header)", len(full)-len(payload))
	}
}

// formatTS — tested via display.FormatTS

func TestFormatTS_Default(t *testing.T) {
	ts := time.Date(2024, 6, 15, 12, 30, 45, 123456000, time.UTC)
	got := display.FormatTS(ts, time.Time{}, "default")
	if !strings.Contains(got, "12:30:45.123456") {
		t.Errorf("default: want HH:MM:SS.us time, got %q", got)
	}
}

func TestFormatTS_T(t *testing.T) {
	ts := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)
	got := display.FormatTS(ts, time.Time{}, "t")
	if got != "" {
		t.Errorf("-t: want empty string, got %q", got)
	}
}

func TestFormatTS_TT(t *testing.T) {
	ts := time.Unix(1718450000, 123456000)
	got := display.FormatTS(ts, time.Time{}, "tt")
	if !strings.Contains(got, "1718450000") {
		t.Errorf("-tt: want unix timestamp, got %q", got)
	}
}

func TestFormatTS_TTT_FirstPacket(t *testing.T) {
	ts := time.Unix(1000, 0)
	got := display.FormatTS(ts, time.Time{}, "ttt")
	if !strings.Contains(got, "0.000000") {
		t.Errorf("-ttt first packet: want 0.000000, got %q", got)
	}
}

func TestFormatTS_TTT_Delta(t *testing.T) {
	prev := time.Unix(1000, 0)
	curr := time.Unix(1000, 500000000)
	got := display.FormatTS(curr, prev, "ttt")
	if !strings.Contains(got, "0.500000") {
		t.Errorf("-ttt delta: want 0.500000, got %q", got)
	}
}

func TestFormatTS_TTTT(t *testing.T) {
	ts := time.Date(2024, 6, 15, 12, 30, 45, 123456000, time.UTC)
	got := display.FormatTS(ts, time.Time{}, "tttt")
	if !strings.Contains(got, "2024-06-15") {
		t.Errorf("-tttt: want date, got %q", got)
	}
}

// printNormal / printVerbose / printPacket — integration with display

func TestPrintNormal_TCP(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	pkt := decodePacket(buildTCPPacket("192.168.1.1", "8.8.8.8", 12345, 80, true, false))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	display.PrintNormal(1, pkt, display.Colorize(ts.Format("15:04:05.000000"), display.ColorGray), true)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "12345") {
		t.Errorf("source port missing, output: %q", out)
	}
	if !strings.Contains(out, "80") {
		t.Errorf("brak portu docelowego, output: %q", out)
	}
	if !strings.Contains(out, "192.168.1.1") {
		t.Errorf("source IP missing, output: %q", out)
	}
}

func TestPrintNormal_UDP(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	pkt := decodePacket(buildUDPPacket("10.0.0.1", "1.1.1.1", 54321, 53))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	display.PrintNormal(2, pkt, display.Colorize(ts.Format("15:04:05.000000"), display.ColorGray), true)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "54321") {
		t.Errorf("source port missing, output: %q", out)
	}
}

func TestPrintNormal_ARP(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	raw := buildARPPacket("192.168.1.1", "192.168.1.2", "aa:bb:cc:dd:ee:ff")
	pkt := decodePacket(raw)
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	display.PrintNormal(1, pkt, display.Colorize(ts.Format("15:04:05.000000"), display.ColorGray), true)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "ARP") {
		t.Errorf("ARP missing from output: %q", out)
	}
	if !strings.Contains(out, "Request") {
		t.Errorf("'Request' missing from ARP output: %q", out)
	}
	if !strings.Contains(out, "length 28") {
		t.Errorf("ARP length should be 28: %q", out)
	}
}

func TestPrintVerbose_TCP(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	pkt := decodePacket(buildTCPPacket("10.0.0.1", "10.0.0.2", 1234, 443, true, false))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	display.PrintVerbose(1, pkt, display.Colorize(ts.Format("15:04:05.000000"), display.ColorGray), true)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "tos") {
		t.Errorf("verbose TCP brak 'tos': %q", out)
	}
	if !strings.Contains(out, "Flags") {
		t.Errorf("verbose TCP brak 'Flags': %q", out)
	}
	if !strings.Contains(out, "seq") {
		t.Errorf("verbose TCP brak 'seq': %q", out)
	}
}

func TestPrintVerbose_UDP(t *testing.T) {
	buf, restore := display.CaptureOut()
	defer restore()

	pkt := decodePacket(buildUDPPacket("10.0.0.1", "10.0.0.2", 12345, 53))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	display.PrintVerbose(1, pkt, display.Colorize(ts.Format("15:04:05.000000"), display.ColorGray), true)
	display.FlushOut()

	out := buf.String()
	if !strings.Contains(out, "proto UDP") {
		t.Errorf("verbose UDP brak 'proto UDP': %q", out)
	}
}

func TestPrintPacket_TimestampModes(t *testing.T) {
	pkt := decodePacket(buildTCPPacket("1.2.3.4", "5.6.7.8", 1000, 80, false, true))
	ts := time.Date(2024, 6, 15, 12, 0, 0, 123456000, time.UTC)
	prev := time.Time{}

	tests := []struct {
		tsMode      string
		shouldEmpty bool
		mustContain string
	}{
		{"default", false, "12:00:00"},
		{"t", true, ""},
		{"tt", false, "."},
		{"ttt", false, "0.000000"},
		{"tttt", false, "2024-"},
	}

	for _, tt := range tests {
		t.Run(tt.tsMode, func(t *testing.T) {
			buf, restore := display.CaptureOut()
			defer restore()
			display.PrintPacket(1, pkt, ts, prev, "normal", tt.tsMode, false, true)
			display.FlushOut()
			got := buf.String()
			if !tt.shouldEmpty && !strings.Contains(got, tt.mustContain) {
				t.Errorf("tsMode=%q: want %q in %q", tt.tsMode, tt.mustContain, got)
			}
		})
	}
}

func TestPrintPacket_ViewModes(t *testing.T) {
	pkt := decodePacket(buildTCPPacket("1.2.3.4", "5.6.7.8", 1000, 80, true, false))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	prev := time.Time{}

	tests := []struct {
		viewMode    string
		mustContain string
	}{
		{"normal", "1.2.3.4"},
		{"verbose", "tos"},
		{"hex", "0000"},
		{"hexascii", "|"},
		{"hex_link", "0000"},
		{"hexascii_link", "|"},
	}

	for _, tt := range tests {
		t.Run(tt.viewMode, func(t *testing.T) {
			buf, restore := display.CaptureOut()
			defer restore()
			display.PrintPacket(1, pkt, ts, prev, tt.viewMode, "default", false, true)
			display.FlushOut()
			got := buf.String()
			if !strings.Contains(got, tt.mustContain) {
				t.Errorf("viewMode=%q: want %q in %q", tt.viewMode, tt.mustContain, got)
			}
		})
	}
}

func TestPrintPacket_VerboseWithHex(t *testing.T) {
	pkt := decodePacket(buildTCPPacket("1.2.3.4", "5.6.7.8", 1000, 80, true, false))
	ts := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	buf, restore := display.CaptureOut()
	defer restore()
	display.PrintPacket(1, pkt, ts, time.Time{}, "hexascii_link", "default", true, true)
	display.FlushOut()

	got := buf.String()
	if !strings.Contains(got, "tos") {
		t.Errorf("-v -XX: brak verbose header (tos): %q", got)
	}
	if !strings.Contains(got, "|") {
		t.Errorf("-v -XX: brak hex+ASCII dump: %q", got)
	}
}

// pcapWriter (rotation)

func TestPcapWriter_CreateAndWrite(t *testing.T) {
	path := t.TempDir() + "/out.pcap"
	pw := rotation.NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	pw.Open()

	raw := buildTCPPacket("1.2.3.4", "5.6.7.8", 1234, 80, true, false)
	pw.WritePacket(time.Now(), raw)
	pw.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	minSize := int64(24 + 16 + len(raw))
	if fi.Size() < minSize {
		t.Errorf("file size = %d, want >= %d", fi.Size(), minSize)
	}
}

func TestPcapWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/capture.pcap"
	raw := buildTCPPacket("1.2.3.4", "5.6.7.8", 1234, 80, true, false)

	pw := rotation.NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 1, 0)
	pw.Open()
	pw.WritePacket(time.Now(), raw)
	pw.WritePacket(time.Now(), raw)
	pw.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Errorf("expected >= 2 files after rotation, got %d", len(entries))
	}
}
