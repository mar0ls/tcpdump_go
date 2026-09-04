package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"tcpdump_go/internal/pathguard"
	"tcpdump_go/offline"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var testFixturePath string

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "tcpdump-go-tests-")
	if err != nil {
		panic(err)
	}
	testFixturePath = filepath.Join(directory, "fixture.pcap")
	createTestPcap(testFixturePath)

	compareBinaryDir = directory
	compareBinaryPath = filepath.Join(directory, "tcpdump_go")
	command := exec.Command("go", "build", "-o", compareBinaryPath, ".")
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "comparison binary unavailable: %v\n%s", buildErr, output)
		compareBinaryPath = ""
	}

	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

func TestExpandArgs(t *testing.T) {
	got := expandArgs([]string{"-nXX", "-vv", "--stats-only", "-c", "2", "tcp"})
	want := []string{"-n", "-XX", "-v", "-v", "--stats-only", "-c", "2", "tcp"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("expandArgs = %q, want %q", got, want)
	}
}

// TestExpandArgsGluedValues covers the getopt forms tcpdump users type by
// habit, where a value is attached to its flag or trails a boolean cluster.
func TestExpandArgsGluedValues(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"bool cluster then value flag", []string{"-nni", "eth0"}, []string{"-nn", "-i", "eth0"}},
		{"glued count", []string{"-c100"}, []string{"-c", "100"}},
		{"glued snaplen after bool", []string{"-vs96"}, []string{"-v", "-s", "96"}},
		{"glued stdout output", []string{"-w-"}, []string{"-w", "-"}},
		{"glued user", []string{"-Znobody"}, []string{"-Z", "nobody"}},
		{"value flag ends cluster", []string{"-ttni", "lo0"}, []string{"-tt", "-n", "-i", "lo0"}},
		{"path keeps its characters", []string{"-r/tmp/a.pcap"}, []string{"-r", "/tmp/a.pcap"}},

		// Left alone: nothing to split, or not fully recognized.
		{"single long flag", []string{"-tttt"}, []string{"-tttt"}},
		{"single short flag", []string{"-XX"}, []string{"-XX"}},
		{"explicit assignment", []string{"--immediate-mode=false"}, []string{"--immediate-mode=false"}},
		{"unknown cluster", []string{"-zq"}, []string{"-zq"}},
		{"bare value flag", []string{"-i"}, []string{"-i"}},
		{"positional expression", []string{"tcp", "port", "80"}, []string{"tcp", "port", "80"}},
		{"double dash", []string{"--"}, []string{"--"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandArgs(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("expandArgs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestGluedArgumentsReachTheParser proves the expansion is wired into parsing,
// not just correct in isolation.
func TestGluedArgumentsReachTheParser(t *testing.T) {
	options, err := parseOptions([]string{"-nnc3", "-r" + testFixturePath}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !options.disableDNSAll {
		t.Error("-nn was not applied")
	}
	if options.count != 3 {
		t.Errorf("count = %d, want 3", options.count)
	}
	if options.readPcap != testFixturePath {
		t.Errorf("readPcap = %q, want %q", options.readPcap, testFixturePath)
	}
}

func TestImmediateModeDefaultsOnAndCanBeDisabled(t *testing.T) {
	options, err := parseOptions([]string{"-i", "lo0"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if options.noImmediateMode {
		t.Error("immediate mode is off by default; it must stay on")
	}
	options, err = parseOptions([]string{"-i", "lo0", "--immediate-mode=false"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !options.noImmediateMode {
		t.Error("--immediate-mode=false did not disable immediate mode")
	}
}

// -Z gives away exactly the privileges the offload restore needs, so the two
// must not be accepted together.
func TestDropPrivilegesRejectsDisableOffload(t *testing.T) {
	options, err := parseOptions([]string{"-i", "lo0", "-Z", "nobody", "--disable-offload"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	err = finalizeOptions(&options)
	if err == nil {
		t.Fatal("finalizeOptions accepted -Z together with --disable-offload")
	}
	if !strings.Contains(err.Error(), "disable-offload") {
		t.Fatalf("error = %v, want it to name the conflicting option", err)
	}
}

func TestDropUserIsAppliedWhenReadingAFile(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	err := run([]string{"-r", testFixturePath, "-n", "-t", "-Z", "no-such-account-cf19a4"}, stdout, stderr)
	if err == nil {
		t.Fatal("run ignored -Z with an unknown user")
	}
	if stdout.Len() != 0 {
		t.Fatalf("packets were printed before the privilege drop failed: %q", stdout.String())
	}
}

func TestParseOptionsUsesPositionalAndFilterFileBPF(t *testing.T) {
	options, err := parseOptions([]string{"-r", testFixturePath, "tcp", "port", "80"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if options.filter != "tcp port 80" {
		t.Fatalf("positional filter = %q", options.filter)
	}

	filterPath := filepath.Join(t.TempDir(), "capture.bpf")
	if err := os.WriteFile(filterPath, []byte("# comment\ntcp\nport 443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options, err = parseOptions([]string{"-r", testFixturePath, "-F", filterPath}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if options.filter != "tcp port 443" {
		t.Fatalf("file filter = %q", options.filter)
	}
	if _, err := parseOptions([]string{"-F", filterPath, "udp"}, io.Discard); err == nil {
		t.Fatal("-F plus positional filter unexpectedly succeeded")
	}
}

func TestRunOfflinePresentationAndFilter(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := run([]string{"-r", testFixturePath, "-n", "-t", "tcp"}, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	if !strings.Contains(output, "192.168.1.1.12345") || strings.Contains(output, "10.0.0.1.54321") {
		t.Fatalf("filtered output = %q", output)
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"-r", testFixturePath, "-n", "-t", "-q"}, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(stdout.String()), "\n") + 1; lines != 2 {
		t.Fatalf("-q printed %d lines: %q", lines, stdout.String())
	}
	// tcpdump's quick mode abbreviates TCP but keeps UDP's full wording.
	if !strings.Contains(stdout.String(), "tcp 5") || !strings.Contains(stdout.String(), "UDP, length") {
		t.Fatalf("-q is incorrectly silent: %q", stdout.String())
	}
}

func TestRawOutputDefaultsToNoPacketTextAndPreservesMetadata(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "copy.pcap")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := run([]string{"-r", testFixturePath, "-w", outputPath, "-n", "-t"}, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("-w unexpectedly printed packets: %q", stdout.String())
	}

	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	_, ci, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	wantTS := time.Date(2024, 1, 1, 12, 0, 0, 123456789, time.UTC)
	if ci.Length != 1500 || !ci.Timestamp.Equal(wantTS) || reader.Snaplen() != 65535 {
		t.Fatalf("rewritten metadata = %+v, snaplen=%d", ci, reader.Snaplen())
	}
}

func TestRawOutputPrintExtension(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "copy.pcap")
	stdout := &bytes.Buffer{}
	if err := run([]string{"-r", testFixturePath, "-w", outputPath, "--print", "-n", "-t"}, stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "192.168.1.1") {
		t.Fatalf("--print output = %q", stdout.String())
	}
}

func TestRunRejectsEveryInputOutputCollision(t *testing.T) {
	t.Run("same path", func(t *testing.T) {
		if err := run([]string{"-r", testFixturePath, "-w", testFixturePath}, io.Discard, io.Discard); err == nil {
			t.Fatal("same input/output unexpectedly succeeded")
		}
	})

	t.Run("hard link", func(t *testing.T) {
		hardlink := filepath.Join(t.TempDir(), "alias.pcap")
		if err := os.Link(testFixturePath, hardlink); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if err := run([]string{"-r", testFixturePath, "-w", hardlink}, io.Discard, io.Discard); err == nil {
			t.Fatal("hard-linked output unexpectedly succeeded")
		}
	})

	t.Run("CSV", func(t *testing.T) {
		if err := run([]string{"-r", testFixturePath, "--stats-only", "--csv", testFixturePath}, io.Discard, io.Discard); err == nil {
			t.Fatal("CSV/input collision unexpectedly succeeded")
		}
	})

	t.Run("future rotation segment", func(t *testing.T) {
		directory := t.TempDir()
		input := filepath.Join(directory, "capture_001.pcap")
		data, err := os.ReadFile(testFixturePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(input, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"-r", input, "-w", filepath.Join(directory, "capture.pcap"), "-C", "1"}, io.Discard, io.Discard); err == nil {
			t.Fatal("rotation namespace collision unexpectedly succeeded")
		}
	})
	t.Run("case-insensitive rotation namespace", func(t *testing.T) {
		directory := t.TempDir()
		input := filepath.Join(directory, "capture_001.PCAP")
		output := filepath.Join(directory, "capture.pcap")
		if err := pathguard.ValidateOutputPaths(input, output, "", true); err == nil {
			t.Fatal("case-only rotation collision unexpectedly succeeded")
		}
	})
}

func TestCorruptPcapReturnsFailureAfterReadablePackets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.pcap")
	data, err := os.ReadFile(testFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	err = run([]string{"-r", path, "-n", "-t"}, stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "record 2") {
		t.Fatalf("corrupt input error = %v", err)
	}
	if !strings.Contains(stdout.String(), "192.168.1.1") {
		t.Fatalf("first complete packet was not printed: %q", stdout.String())
	}
}

func TestWriterIsClosedWhenCSVFails(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "out.pcap")
	missingCSV := filepath.Join(t.TempDir(), "missing", "flows.csv")
	err := run([]string{"-r", testFixturePath, "-w", outputPath, "--csv", missingCSV}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("invalid CSV destination unexpectedly succeeded")
	}
	file, openErr := os.Open(outputPath)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer func() { _ = file.Close() }()
	reader, readErr := pcapgo.NewReader(file)
	if readErr != nil {
		t.Fatalf("raw output was not flushed before error: %v", readErr)
	}
	count := 0
	for {
		_, _, readErr = reader.ReadPacketData()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("raw output packets = %d, want 2", count)
	}
}

func TestMixedLinkPcapngIsPreservedOrExplicitlyRejected(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "mixed.pcapng")
	createMixedPcapng(input)

	t.Run("pcapng", func(t *testing.T) {
		output := filepath.Join(directory, "copy.pcapng")
		if err := run([]string{"-r", input, "-w", output, "-n"}, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
		reader, err := offline.Open(output)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reader.Close() }()
		var linkTypes []layers.LinkType
		for {
			_, _, linkType, err := reader.ReadPacketData()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			linkTypes = append(linkTypes, linkType)
		}
		if len(linkTypes) != 2 || linkTypes[0] != layers.LinkTypeEthernet || linkTypes[1] != layers.LinkTypeRaw {
			t.Fatalf("output link types = %v", linkTypes)
		}
	})

	t.Run("classic", func(t *testing.T) {
		output := filepath.Join(directory, "copy.pcap")
		err := run([]string{"-r", input, "-w", output, "-n"}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "cannot contain both") {
			t.Fatalf("classic mixed-link error = %v", err)
		}
	})
}

func TestWriteCSVIsDeterministicAndParseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.csv")
	flows := map[flowKey]uint64{
		{Src: "3.3.3.3", Dst: "4.4.4.4", Sport: "2", Dport: "53", Proto: "UDP"}: 2,
		{Src: "1.1.1.1", Dst: "2.2.2.2", Sport: "1", Dport: "80", Proto: "TCP"}: 5,
	}
	if err := writeCSV(path, flows); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || records[1][0] != "1.1.1.1" || records[2][0] != "3.3.3.3" {
		t.Fatalf("CSV records = %v", records)
	}
}

func TestCountAndStatsOnly(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := run([]string{"-r", testFixturePath, "--count", "tcp"}, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "1 packets\n" {
		t.Fatalf("count output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"-r", testFixturePath, "--stats-only", "-n"}, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Session summary") || strings.Contains(stdout.String(), "192.168.1.1.12345") {
		t.Fatalf("stats-only output = %q", stdout.String())
	}
}

func TestOptionsWithoutCaptureSourceOrRequiredOutputFail(t *testing.T) {
	output := filepath.Join(t.TempDir(), "unused.pcap")
	tests := [][]string{
		{"-w", output},
		{"-r", testFixturePath, "--pcapng"},
		{"-r", testFixturePath, "--print"},
	}
	for _, args := range tests {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", args)
		}
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source-less -w created output: %v", err)
	}
}

func TestCountDoesNotCorruptRawStdout(t *testing.T) {
	if compareBinaryPath == "" {
		t.Skip("comparison binary unavailable")
	}
	command := exec.Command(compareBinaryPath, "-r", testFixturePath, "-w", "-", "--count")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("raw stdout command failed: %v: %s", err, stderr.String())
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("raw stdout is not pcap: %v", err)
	}
	for packet := 1; packet <= 2; packet++ {
		if _, _, err := reader.ReadPacketData(); err != nil {
			t.Fatalf("read raw stdout packet %d: %v", packet, err)
		}
	}
	if _, _, err := reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		t.Fatalf("raw stdout has trailing non-pcap data: %v", err)
	}
	if stderr.String() != "2 packets\n" {
		t.Fatalf("count status = %q", stderr.String())
	}
}

func TestEmptyPcapngRewriteCreatesValidOutputAndValidatesBPF(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "empty.pcapng")
	file, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	intf := pcapgo.DefaultNgInterface
	intf.LinkType = layers.LinkTypeEthernet
	intf.SnapLength = 9000
	writer, err := pcapgo.NewNgWriterInterface(file, intf, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(directory, "copy.pcapng")
	if err := run([]string{"-r", input, "-w", output}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	reader, err := offline.Open(output)
	if err != nil {
		t.Fatalf("open empty rewrite: %v", err)
	}
	defer func() { _ = reader.Close() }()
	if _, _, _, err := reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		t.Fatalf("empty rewrite read = %v, want EOF", err)
	}
	copiedInterface, err := reader.Interface(0)
	if err != nil {
		t.Fatalf("read copied interface: %v", err)
	}
	if copiedInterface.LinkType != layers.LinkTypeEthernet || copiedInterface.SnapLength != 9000 {
		t.Fatalf("copied interface = %+v", copiedInterface)
	}

	if err := run([]string{"-r", input, "tcp and and"}, io.Discard, io.Discard); err == nil {
		t.Fatal("invalid BPF on an empty pcapng unexpectedly succeeded")
	}
}

func createTestPcap(path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	writer := pcapgo.NewWriterNanos(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}
	timestamp := time.Date(2024, 1, 1, 12, 0, 0, 123456789, time.UTC)
	packets := []struct {
		data       []byte
		wireLength int
	}{
		{data: buildTCPPacket("192.168.1.1", "8.8.8.8", 12345, 80, true, false), wireLength: 1500},
		{data: buildUDPPacket("10.0.0.1", "1.1.1.1", 54321, 53), wireLength: 43},
	}
	for _, packet := range packets {
		ci := gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(packet.data), Length: max(packet.wireLength, len(packet.data))}
		if err := writer.WritePacket(ci, packet.data); err != nil {
			panic(err)
		}
		timestamp = timestamp.Add(time.Millisecond)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
}

func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) []byte {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack, Window: 65535}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, gopacket.Payload([]byte("hello"))); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func buildUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, udp, gopacket.Payload([]byte{0})); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func createMixedPcapng(path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	first := pcapgo.DefaultNgInterface
	first.LinkType = layers.LinkTypeEthernet
	first.SnapLength = 65535
	writer, err := pcapgo.NewNgWriterInterface(file, first, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		panic(err)
	}
	second := pcapgo.DefaultNgInterface
	second.LinkType = layers.LinkTypeRaw
	second.SnapLength = 65535
	secondID, err := writer.AddInterface(second)
	if err != nil {
		panic(err)
	}
	ethernetPacket := buildTCPPacket("192.0.2.1", "198.51.100.2", 1000, 80, true, false)
	rawPacket := buildUDPPacket("192.0.2.3", "198.51.100.4", 2000, 53)[14:]
	for _, packet := range []struct {
		data           []byte
		interfaceIndex int
	}{
		{data: ethernetPacket, interfaceIndex: 0},
		{data: rawPacket, interfaceIndex: secondID},
	} {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(int64(packet.interfaceIndex+1), 1), CaptureLength: len(packet.data), Length: len(packet.data), InterfaceIndex: packet.interfaceIndex}
		if err := writer.WritePacket(ci, packet.data); err != nil {
			panic(err)
		}
	}
	if err := writer.Flush(); err != nil {
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
}

// -Z on an unprivileged process is a warning, not a failure: tcpdump ignores
// it because there is nothing to drop, and packets must still be printed.
func TestDropUserWithoutRootWarnsAndContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the drop would succeed")
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if err := run([]string{"-r", testFixturePath, "-n", "-t", "-Z", "nobody"}, stdout, stderr); err != nil {
		t.Fatalf("run failed instead of warning: %v", err)
	}
	if !strings.Contains(stderr.String(), "-Z ignored") {
		t.Fatalf("no warning about the skipped privilege drop: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "192.168.1.1") {
		t.Fatalf("packets were not printed: %q", stdout.String())
	}
}
