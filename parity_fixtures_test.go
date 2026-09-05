package main

import (
	"encoding/binary"
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

// ntpParityPacket wraps a raw NTP message in UDP/IPv4/Ethernet. The message is
// laid out by hand because several of the fixtures are deliberately malformed
// or truncated, which no serializer would produce.
func ntpParityPacket(t *testing.T, message []byte, srcPort layers.UDPPort) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2},
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: 123}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return serializeParity(t, parityEthernet(), ip, udp, gopacket.Payload(message))
}

// ntpParityMessage builds a 48-byte NTP header. Timestamps carry a raw 32-bit
// fraction, the way the wire does.
func ntpParityMessage(leap, version, mode, stratum uint8, poll, precision int8, refID []byte, timestamps [4]uint64) []byte {
	message := make([]byte, 48)
	message[0] = leap<<6 | version<<3 | mode
	message[1] = stratum
	message[2] = byte(poll)
	message[3] = byte(precision)
	binary.BigEndian.PutUint32(message[4:], 0x00012000)
	binary.BigEndian.PutUint32(message[8:], 0x00008000)
	copy(message[12:16], refID)
	for i, value := range timestamps {
		binary.BigEndian.PutUint64(message[16+i*8:], value)
	}
	return message
}

// arpParityPacket wraps a hand-built ARP PDU in an Ethernet frame padded to
// the 60-byte minimum, which is what a real capture holds. The PDU is laid out
// by hand so that odd address sizes and opcodes survive untouched.
func arpParityPacket(hardware, protocol uint16, hardwareLen, protocolLen uint8, operation uint16, sha, spa, tha, tpa []byte) []byte {
	frame := make([]byte, 14)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	binary.BigEndian.PutUint16(frame[12:], 0x0806)

	pdu := make([]byte, 8)
	binary.BigEndian.PutUint16(pdu[0:], hardware)
	binary.BigEndian.PutUint16(pdu[2:], protocol)
	pdu[4] = hardwareLen
	pdu[5] = protocolLen
	binary.BigEndian.PutUint16(pdu[6:], operation)
	pdu = append(pdu, sha...)
	pdu = append(pdu, spa...)
	pdu = append(pdu, tha...)
	pdu = append(pdu, tpa...)

	frame = append(frame, pdu...)
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame
}

// ntpParityControl builds an NTP mode-6 control message.
func ntpParityControl(flags byte, sequence, status, assoc, offset, count uint16, dataLen int) []byte {
	message := make([]byte, 12+dataLen)
	message[0] = 4<<3 | 6
	message[1] = flags
	binary.BigEndian.PutUint16(message[2:], sequence)
	binary.BigEndian.PutUint16(message[4:], status)
	binary.BigEndian.PutUint16(message[6:], assoc)
	binary.BigEndian.PutUint16(message[8:], offset)
	binary.BigEndian.PutUint16(message[10:], count)
	return message
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

	// NTP: every leap value and stratum class, the poll interval either side of
	// the range tcpdump spells out, both delta signs, a zero originator, a
	// truncated message, and the authenticated tails. Control messages are left
	// out on purpose: their header is not decoded.
	const (
		ntpMoment = uint64(3925854410)<<32 | 0x40000000
		ntpLater  = uint64(3925854420)<<32 | 0x80000000
	)
	ntpMessages := [][]byte{
		ntpParityMessage(0, 4, 3, 0, 6, -20, nil, [4]uint64{0, 0, 0, ntpMoment}),
		ntpParityMessage(0, 4, 4, 2, 6, -23, []byte{192, 168, 1, 1}, [4]uint64{ntpMoment, ntpMoment, ntpMoment, ntpMoment}),
		ntpParityMessage(0, 4, 4, 1, 10, -29, []byte("GPS "), [4]uint64{ntpMoment, ntpMoment, ntpMoment, ntpMoment}),
		ntpParityMessage(0, 4, 4, 1, 6, -20, []byte{1, 2, 0x80, 0xff}, [4]uint64{ntpMoment, ntpMoment, ntpMoment, ntpMoment}),
		ntpParityMessage(1, 3, 4, 16, 4, -10, []byte("INIT"), [4]uint64{ntpMoment, 0, ntpMoment, ntpMoment}),
		ntpParityMessage(2, 4, 5, 3, 0, -20, []byte{10, 1, 1, 1}, [4]uint64{ntpMoment, ntpLater, ntpMoment, ntpMoment}),
		ntpParityMessage(3, 4, 1, 15, -3, 0, []byte{10, 1, 1, 1}, [4]uint64{ntpMoment, ntpMoment, ntpLater, ntpLater}),
		ntpParityMessage(0, 4, 2, 255, 32, 127, []byte{10, 1, 1, 1}, [4]uint64{ntpMoment, ntpMoment, ntpMoment, ntpMoment}),
		ntpParityMessage(0, 4, 7, 0, 0, 0, nil, [4]uint64{}),
		ntpParityMessage(0, 4, 4, 2, 6, -20, nil, [4]uint64{})[:47],
		make([]byte, 40),
		{0x23, 0x00},
	}
	// key id alone, key id with a 128-bit digest, key id with a 160-bit digest,
	// and a tail tcpdump only counts
	authenticated := ntpParityMessage(0, 4, 4, 2, 6, -20, []byte{1, 2, 3, 4}, [4]uint64{ntpMoment, ntpMoment, ntpMoment, ntpMoment})
	for _, extra := range []int{4, 20, 24, 12} {
		message := append(append([]byte{}, authenticated...), make([]byte, extra)...)
		binary.BigEndian.PutUint32(message[48:], 7)
		for i := 52; i < len(message); i++ {
			message[i] = byte(i)
		}
		ntpMessages = append(ntpMessages, message)
	}
	ntpPackets := make([][]byte, 0, len(ntpMessages))
	for i, message := range ntpMessages {
		ntpPackets = append(ntpPackets, ntpParityPacket(t, message, layers.UDPPort(40000+i)))
	}
	// Control messages: both directions, the error and continuation bits, a
	// payload tcpdump acknowledges without decoding, and a count that overruns.
	for _, control := range [][]byte{
		ntpParityControl(0x02, 1772, 0, 0, 0, 0, 0),
		ntpParityControl(0x82, 1772, 0x0615, 1, 0, 0, 0),
		ntpParityControl(0xE2, 1772, 0x0615, 1, 0, 0, 0),
		ntpParityControl(0x42, 1, 0, 0, 0, 0, 0),
		ntpParityControl(0x02, 1, 0, 0, 16, 8, 8),
		ntpParityControl(0x02, 1, 0, 0, 0, 4096, 8),
		ntpParityControl(0x1f, 1, 0, 0, 0, 0, 0),
		ntpParityControl(0x02, 7, 0, 0, 0, 0, 0)[:11],
	} {
		ntpPackets = append(ntpPackets, ntpParityPacket(t, control, layers.UDPPort(41000+len(ntpPackets))))
	}
	writeParityPcap(t, filepath.Join(directory, "ntp.pcap"), ntpPackets)

	// ARP: the request and reply forms, the reverse and inverse opcodes,
	// hardware and protocol types named and unnamed, and the protocol widths
	// tcpdump refuses to render. Two groups are deliberately absent: opcodes
	// tcpdump answers with a hex dump (see the README scope note), and
	// self-directed requests, which Apple's fork labels "Announcement" and
	// "Probe" while upstream tcpdump does not. Comparing those would fail on
	// one platform or the other; TestARPOperationsMatchTcpdump pins the
	// upstream wording this follows.
	mac := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	other := []byte{0x09, 0x09, 0x09, 0x09, 0x09, 0x09}
	zeroMAC := make([]byte, 6)
	first := []byte{10, 0, 0, 1}
	second := []byte{10, 0, 0, 2}
	arpPackets := [][]byte{
		arpParityPacket(1, 0x0800, 6, 4, 1, mac, first, zeroMAC, second),  // request
		arpParityPacket(1, 0x0800, 6, 4, 1, mac, first, other, second),    // request naming a target
		arpParityPacket(1, 0x0800, 6, 4, 2, mac, first, zeroMAC, second),  // reply
		arpParityPacket(1, 0x0800, 6, 4, 3, mac, first, zeroMAC, second),  // reverse request
		arpParityPacket(1, 0x0800, 6, 4, 4, mac, first, zeroMAC, second),  // reverse reply
		arpParityPacket(1, 0x0800, 6, 4, 8, mac, first, zeroMAC, second),  // inverse request
		arpParityPacket(1, 0x0800, 6, 4, 9, mac, first, zeroMAC, second),  // inverse reply
		arpParityPacket(6, 0x0800, 6, 4, 1, mac, first, zeroMAC, second),  // TokenRing
		arpParityPacket(7, 0x0800, 6, 4, 1, mac, first, zeroMAC, second),  // ArcNet
		arpParityPacket(15, 0x0800, 6, 4, 1, mac, first, zeroMAC, second), // FrameRelay
		arpParityPacket(23, 0x0800, 6, 4, 1, mac, first, zeroMAC, second), // Strip
		arpParityPacket(24, 0x0800, 6, 4, 1, mac, first, zeroMAC, second), // IEEE 1394
		arpParityPacket(99, 0x0800, 6, 4, 1, mac, first, zeroMAC, second), // unnamed hardware
		arpParityPacket(1, 0x86dd, 6, 16, 1, mac, make([]byte, 16), zeroMAC, make([]byte, 16)),
		arpParityPacket(1, 0x1234, 6, 4, 1, mac, first, zeroMAC, second),                     // unnamed protocol
		arpParityPacket(1, 0x1234, 6, 4, 2, mac, first, zeroMAC, second),                     // unnamed protocol, reply
		arpParityPacket(1, 0x0800, 6, 6, 1, mac, make([]byte, 6), zeroMAC, make([]byte, 6)),  // IPv4 at the wrong width
		arpParityPacket(1, 0x0800, 4, 4, 1, make([]byte, 4), first, make([]byte, 4), second), // short hardware address
	}
	writeParityPcap(t, filepath.Join(directory, "arp.pcap"), arpPackets)

	return []string{"basic.pcap", "http_cksum.pcap", "udp_cksum.pcap", "dns.pcap", "dns_records.pcap", "dns_ttl.pcap", "ntp.pcap", "arp.pcap"}
}
