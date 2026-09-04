package display

import (
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// httpPorts mirrors tcpdump's HTTP_PORT / HTTP_PORT_ALT.
var httpPorts = map[uint16]bool{80: true, 8080: true}

// dnsSummary renders a DNS message the way tcpdump's domain printer does:
// "4660+ A? example.com. (29)" for a query and "4660 2/0/0 A 1.2.3.4 (83)"
// for a response. From -v on, answers carry their owner name.
func dnsSummary(dns *layers.DNS, messageLength, verbosity int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d", dns.ID)
	b.WriteString(dnsFlagMarkers(dns))

	if !dns.QR {
		b.WriteString(" ")
		if dns.OpCode != layers.DNSOpCodeQuery {
			fmt.Fprintf(&b, "%s ", dnsOpCodeName(dns.OpCode))
		}
		b.WriteString(dnsQuestions(dns))
		fmt.Fprintf(&b, " (%d)", messageLength)
		return b.String()
	}

	if dns.ResponseCode != layers.DNSResponseCodeNoErr {
		fmt.Fprintf(&b, " %s", dnsResponseCodeName(dns.ResponseCode))
	}
	// From -vv on, tcpdump echoes the question section back.
	if verbosity > 1 && len(dns.Questions) > 0 {
		fmt.Fprintf(&b, " q: %s", dnsQuestions(dns))
	}
	fmt.Fprintf(&b, " %d/%d/%d", dns.ANCount, dns.NSCount, dns.ARCount)
	if records := dnsRecords(dns.Answers, verbosity); records != "" {
		fmt.Fprintf(&b, " %s", records)
	}
	fmt.Fprintf(&b, " (%d)", messageLength)
	return b.String()
}

// dnsFlagMarkers reproduces tcpdump's single-character header flags.
func dnsFlagMarkers(dns *layers.DNS) string {
	markers := ""
	if dns.AA {
		markers += "*"
	}
	if !dns.RD && dns.QR {
		markers += "-"
	}
	if dns.RD && !dns.QR {
		markers += "+"
	}
	if dns.TC {
		markers += "|"
	}
	return markers
}

func dnsQuestions(dns *layers.DNS) string {
	parts := make([]string, 0, len(dns.Questions))
	for _, question := range dns.Questions {
		parts = append(parts, fmt.Sprintf("%s? %s.", question.Type, question.Name))
	}
	return strings.Join(parts, ", ")
}

func dnsRecords(records []layers.DNSResourceRecord, verbosity int) string {
	parts := make([]string, 0, len(records))
	for _, record := range records {
		value := dnsRecordValue(record)
		if value == "" {
			continue
		}
		if verbosity > 2 {
			// -vvv adds the record TTL, in tcpdump's relative-time notation.
			parts = append(parts, fmt.Sprintf("%s. [%s] %s %s", record.Name, relativeTime(record.TTL), record.Type, value))
			continue
		}
		if verbosity > 0 {
			parts = append(parts, fmt.Sprintf("%s. %s %s", record.Name, record.Type, value))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s", record.Type, value))
	}
	return strings.Join(parts, ", ")
}

func dnsRecordValue(record layers.DNSResourceRecord) string {
	switch record.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if record.IP == nil {
			return ""
		}
		return record.IP.String()
	case layers.DNSTypeCNAME:
		return string(record.CNAME) + "."
	case layers.DNSTypeNS:
		return string(record.NS) + "."
	case layers.DNSTypePTR:
		return string(record.PTR) + "."
	case layers.DNSTypeMX:
		// tcpdump prints the exchange before the preference.
		return fmt.Sprintf("%s. %d", record.MX.Name, record.MX.Preference)
	case layers.DNSTypeTXT:
		quoted := make([]string, 0, len(record.TXTs))
		for _, txt := range record.TXTs {
			quoted = append(quoted, fmt.Sprintf("%q", string(txt)))
		}
		return strings.Join(quoted, " ")
	case layers.DNSTypeSOA:
		return fmt.Sprintf("%s. %s. %d", record.SOA.MName, record.SOA.RName, record.SOA.Serial)
	case layers.DNSTypeSRV:
		return fmt.Sprintf("%d %d %d %s.", record.SRV.Priority, record.SRV.Weight, record.SRV.Port, record.SRV.Name)
	default:
		return record.Type.String()
	}
}

func dnsOpCodeName(code layers.DNSOpCode) string {
	if name := code.String(); name != "" {
		return strings.ToUpper(name)
	}
	return fmt.Sprintf("Opcode%d", uint8(code))
}

func dnsResponseCodeName(code layers.DNSResponseCode) string {
	// gopacket spells these out; tcpdump uses the short RFC mnemonics.
	switch code {
	case layers.DNSResponseCodeFormErr:
		return "FormErr"
	case layers.DNSResponseCodeServFail:
		return "ServFail"
	case layers.DNSResponseCodeNXDomain:
		return "NXDomain"
	case layers.DNSResponseCodeNotImp:
		return "NotImp"
	case layers.DNSResponseCodeRefused:
		return "Refused"
	default:
		return code.String()
	}
}

// httpSummary renders tcpdump's HTTP hint. Without -v it appends the first
// request or status line; with -v it reports the body length and then the
// payload, tab-indented, exactly as tcpdump does.
func httpSummary(payload []byte, verbosity int) string {
	// tcpdump only decodes further once the payload really starts with a
	// request or status line; a continuation segment just gets the hint.
	line := httpFirstLine(payload)
	if line == "" {
		return "HTTP"
	}
	if verbosity > 0 {
		summary := fmt.Sprintf("HTTP, length: %d", len(payload))
		if body := httpPayloadLines(payload); body != "" {
			return summary + "\n" + body
		}
		return summary
	}
	return "HTTP: " + line
}

// httpFirstLine returns the request or status line, or "" when the payload does
// not start with one (a continuation segment, for example).
func httpFirstLine(payload []byte) string {
	line, _, _ := strings.Cut(string(payload), "\n")
	line = strings.TrimRight(line, "\r")
	if line == "" || !isPrintableASCII(line) {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	if strings.HasPrefix(fields[0], "HTTP/") {
		return line
	}
	switch fields[0] {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		return line
	}
	return ""
}

func httpPayloadLines(payload []byte) string {
	text := string(payload)
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	// A payload ending in a newline yields a final empty element that is not a
	// line; tcpdump does print the blank line before it.
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, "\t"+strings.TrimRight(line, "\r"))
	}
	return strings.Join(out, "\n")
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// applicationSummary returns the application-layer text for a TCP segment, or
// "" when no printer matches.
func applicationSummary(packet gopacket.Packet, srcPort, dstPort uint16, payload []byte, verbosity int) string {
	if len(payload) == 0 {
		return ""
	}
	if srcPort == 53 || dstPort == 53 {
		if dns := dnsLayer(packet); dns != nil {
			return dnsSummary(dns, len(payload), verbosity)
		}
	}
	if httpPorts[srcPort] || httpPorts[dstPort] {
		return httpSummary(payload, verbosity)
	}
	return ""
}

func dnsLayer(packet gopacket.Packet) *layers.DNS {
	layer := packet.Layer(layers.LayerTypeDNS)
	if layer == nil {
		return nil
	}
	dns, _ := layer.(*layers.DNS)
	return dns
}

// transportChecksum renders tcpdump's "cksum 0x... (correct)" field. gopacket
// needs the network layer wired in before it can verify a decoded segment, and
// a truncated capture is reported as unverifiable rather than as wrong.
func transportChecksum(nl gopacket.NetworkLayer, tcp *layers.TCP) string {
	if err := tcp.SetNetworkLayerForChecksum(nl); err != nil {
		return ""
	}
	err, result := tcp.VerifyChecksum()
	if err != nil {
		return ""
	}
	if result.Valid {
		return fmt.Sprintf("cksum 0x%04x (correct)", tcp.Checksum)
	}
	return fmt.Sprintf("cksum 0x%04x (incorrect -> 0x%04x)", tcp.Checksum, result.Correct)
}

// ipChecksumProblem returns tcpdump's ", bad cksum ...!" note, which it only
// prints when the header checksum is actually wrong.
func ipChecksumProblem(nl gopacket.NetworkLayer) string {
	ip, ok := nl.(*layers.IPv4)
	if !ok {
		return ""
	}
	err, result := ip.VerifyChecksum()
	if err != nil || result.Valid {
		return ""
	}
	return fmt.Sprintf(", bad cksum %x (->%x)!", ip.Checksum, result.Correct)
}

// udpChecksumNote renders tcpdump's -vv UDP checksum prefix, including the
// trailing space. A zero checksum means the sender opted out, which is legal
// over IPv4 and is reported as such rather than as a failure.
func udpChecksumNote(nl gopacket.NetworkLayer, udp *layers.UDP) string {
	if udp.Checksum == 0 {
		return "[no cksum] "
	}
	if err := udp.SetNetworkLayerForChecksum(nl); err != nil {
		return ""
	}
	err, result := udp.VerifyChecksum()
	if err != nil {
		return ""
	}
	if result.Valid {
		return "[udp sum ok] "
	}
	return fmt.Sprintf("[bad udp cksum 0x%04x -> 0x%04x!] ", udp.Checksum, result.Correct)
}

// relativeTime formats a TTL the way tcpdump's unsigned_relts_print does:
// the largest non-zero units concatenated, for example "1h1m1s".
func relativeTime(seconds uint32) string {
	if seconds == 0 {
		return "0s"
	}
	units := []struct {
		size   uint32
		suffix string
	}{
		{365 * 24 * 3600, "y"},
		{7 * 24 * 3600, "w"},
		{24 * 3600, "d"},
		{3600, "h"},
		{60, "m"},
		{1, "s"},
	}
	var b strings.Builder
	for _, unit := range units {
		if value := seconds / unit.size; value > 0 {
			fmt.Fprintf(&b, "%d%s", value, unit.suffix)
			seconds %= unit.size
		}
	}
	return b.String()
}
