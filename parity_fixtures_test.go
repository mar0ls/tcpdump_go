package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// The parity fixtures are built here rather than committed: testdata/ is
// git-ignored, so a checked-in .pcap would silently vanish on CI and take the
// comparison with it.

func writeParityPcap(t *testing.T, path string, packets [][]byte) {
	t.Helper()
	file, err := os.Create(path) //#nosec G304 // path is under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, packet := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(1700000000, 0),
			CaptureLength: len(packet),
			Length:        len(packet),
		}
		if err := writer.WritePacket(ci, packet); err != nil {
			t.Fatal(err)
		}
	}
}

func parityEthernet() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func serializeParity(t *testing.T, parts ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, parts...); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

// httpPacket builds a TCP segment carrying a request. The two corrupt variants
// exercise tcpdump's "incorrect ->" and "bad cksum" wordings.
func httpPacket(t *testing.T, corruptTCP, corruptIP bool) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 7, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{192, 168, 1, 10}, DstIP: net.IP{93, 184, 216, 34},
	}
	tcp := &layers.TCP{SrcPort: 44321, DstPort: 80, Seq: 1000, Ack: 1, ACK: true, PSH: true, Window: 502}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	body := gopacket.Payload([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n\r\n"))
	data := serializeParity(t, parityEthernet(), ip, tcp, body)
	if corruptIP {
		data[24] ^= 0xff
	}
	if corruptTCP {
		data[50] ^= 0xff
	}
	return data
}

func udpPacket(t *testing.T, corrupt, zeroSum bool) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 3, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2},
	}
	udp := &layers.UDP{SrcPort: 5000, DstPort: 6000}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	data := serializeParity(t, parityEthernet(), ip, udp, gopacket.Payload([]byte("payload-data")))
	if corrupt {
		data[40] ^= 0xff
	}
	if zeroSum {
		data[40], data[41] = 0, 0
	}
	return data
}

func dnsPacket(t *testing.T, dns *layers.DNS, srcPort, dstPort layers.UDPPort) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 9, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 168, 1, 10}, DstIP: net.IP{8, 8, 8, 8},
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return serializeParity(t, parityEthernet(), ip, udp, dns)
}

func dnsQuestion(name string, recordType layers.DNSType) layers.DNSQuestion {
	return layers.DNSQuestion{Name: []byte(name), Type: recordType, Class: layers.DNSClassIN}
}

// buildParityFixtures writes every fixture into directory and returns their
// file names.
func buildParityFixtures(t *testing.T, directory string) []string {
	t.Helper()

	// A minimal TCP packet plus a DNS message too short to decode.
	shortDNS := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{1, 1, 1, 1},
	}
	shortUDP := &layers.UDP{SrcPort: 54321, DstPort: 53}
	if err := shortUDP.SetNetworkLayerForChecksum(shortDNS); err != nil {
		t.Fatal(err)
	}
	basicIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{192, 168, 1, 1}, DstIP: net.IP{8, 8, 8, 8},
	}
	basicTCP := &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true, Window: 65535}
	if err := basicTCP.SetNetworkLayerForChecksum(basicIP); err != nil {
		t.Fatal(err)
	}
	writeParityPcap(t, filepath.Join(directory, "basic.pcap"), [][]byte{
		serializeParity(t, parityEthernet(), basicIP, basicTCP, gopacket.Payload([]byte("hello"))),
		serializeParity(t, parityEthernet(), shortDNS, shortUDP, gopacket.Payload([]byte{0x00})),
	})

	writeParityPcap(t, filepath.Join(directory, "http_cksum.pcap"), [][]byte{
		httpPacket(t, false, false), httpPacket(t, true, false), httpPacket(t, false, true),
	})

	writeParityPcap(t, filepath.Join(directory, "udp_cksum.pcap"), [][]byte{
		udpPacket(t, false, false), udpPacket(t, true, false), udpPacket(t, false, true),
	})

	query := &layers.DNS{
		ID: 0x1234, RD: true, QDCount: 1,
		Questions: []layers.DNSQuestion{dnsQuestion("example.com", layers.DNSTypeA)},
	}
	answer := &layers.DNS{
		ID: 0x1234, QR: true, RD: true, RA: true, QDCount: 1, ANCount: 2,
		Questions: []layers.DNSQuestion{dnsQuestion("example.com", layers.DNSTypeA)},
		Answers: []layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: net.IP{93, 184, 216, 34}},
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: net.IP{93, 184, 216, 35}},
		},
	}
	missing := &layers.DNS{
		ID: 0x4321, QR: true, RD: true, RA: true, ResponseCode: layers.DNSResponseCodeNXDomain, QDCount: 1,
		Questions: []layers.DNSQuestion{dnsQuestion("nope.example.com", layers.DNSTypeAAAA)},
	}
	writeParityPcap(t, filepath.Join(directory, "dns.pcap"), [][]byte{
		dnsPacket(t, query, 55555, 53),
		dnsPacket(t, answer, 53, 55555),
		dnsPacket(t, missing, 53, 55556),
	})

	records := []*layers.DNS{
		{ID: 1, QDCount: 1, Questions: []layers.DNSQuestion{dnsQuestion("ipv6.example.com", layers.DNSTypeAAAA)}},
		{
			ID: 2, QR: true, AA: true, TC: true, RD: true, RA: true, QDCount: 1, ANCount: 2,
			Questions: []layers.DNSQuestion{dnsQuestion("www.example.com", layers.DNSTypeA)},
			Answers: []layers.DNSResourceRecord{
				{Name: []byte("www.example.com"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, TTL: 60, CNAME: []byte("example.com")},
				{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.IP{1, 2, 3, 4}},
			},
		},
		{
			ID: 3, QR: true, RD: true, RA: true, QDCount: 1, ANCount: 2,
			Questions: []layers.DNSQuestion{dnsQuestion("example.com", layers.DNSTypeMX)},
			Answers: []layers.DNSResourceRecord{
				{Name: []byte("example.com"), Type: layers.DNSTypeMX, Class: layers.DNSClassIN, TTL: 60, MX: layers.DNSMX{Preference: 10, Name: []byte("mail.example.com")}},
				{Name: []byte("example.com"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 60, TXTs: [][]byte{[]byte("v=spf1 -all")}},
			},
		},
		{
			ID: 4, QR: true, RD: true, RA: true, QDCount: 1, ANCount: 1,
			Questions: []layers.DNSQuestion{dnsQuestion("4.3.2.1.in-addr.arpa", layers.DNSTypePTR)},
			Answers:   []layers.DNSResourceRecord{{Name: []byte("4.3.2.1.in-addr.arpa"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN, TTL: 60, PTR: []byte("host.example.com")}},
		},
		{
			ID: 5, QR: true, RD: true, RA: true, QDCount: 1, ANCount: 1,
			Questions: []layers.DNSQuestion{dnsQuestion("ipv6.example.com", layers.DNSTypeAAAA)},
			Answers:   []layers.DNSResourceRecord{{Name: []byte("ipv6.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP("2001:db8::1")}},
		},
		{
			ID: 6, QR: true, RD: true, RA: true, ResponseCode: layers.DNSResponseCodeServFail, QDCount: 1,
			Questions: []layers.DNSQuestion{dnsQuestion("broken.example.com", layers.DNSTypeA)},
		},
	}
	recordPackets := make([][]byte, 0, len(records))
	for i, message := range records {
		if message.QR {
			recordPackets = append(recordPackets, dnsPacket(t, message, 53, layers.UDPPort(40000+i)))
			continue
		}
		recordPackets = append(recordPackets, dnsPacket(t, message, layers.UDPPort(40000+i), 53))
	}
	writeParityPcap(t, filepath.Join(directory, "dns_records.pcap"), recordPackets)

	// TTL boundaries for tcpdump's relative-time notation, including the
	// wrap into years that a naive implementation gets wrong.
	ttls := []uint32{0, 1, 59, 60, 61, 300, 3600, 3661, 86400, 90061, 604800, 694861, 4294967295}
	ttlPackets := make([][]byte, 0, len(ttls))
	for i, ttl := range ttls {
		message := &layers.DNS{
			ID: uint16(i), QR: true, RD: true, RA: true, QDCount: 1, ANCount: 1,
			Questions: []layers.DNSQuestion{dnsQuestion("t.example.com", layers.DNSTypeA)},
			Answers:   []layers.DNSResourceRecord{{Name: []byte("t.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl, IP: net.IP{1, 2, 3, 4}}},
		}
		ttlPackets = append(ttlPackets, dnsPacket(t, message, 53, layers.UDPPort(40000+i)))
	}
	writeParityPcap(t, filepath.Join(directory, "dns_ttl.pcap"), ttlPackets)

	return []string{"basic.pcap", "http_cksum.pcap", "udp_cksum.pcap", "dns.pcap", "dns_records.pcap", "dns_ttl.pcap"}
}
