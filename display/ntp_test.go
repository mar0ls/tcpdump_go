package display

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// Every expected string below was taken from tcpdump 4.99.1 / libpcap 1.10.1
// rendering the same bytes, so a change here means a change away from tcpdump.

// ntpMessage builds a 48-byte NTP header. Timestamps are given as whole
// seconds paired with a raw 32-bit fraction, which is how the wire carries them.
func ntpMessage(leap, version, mode, stratum uint8, poll, precision int8, refID []byte, timestamps [4]uint64) []byte {
	message := make([]byte, ntpHeaderLen)
	message[0] = leap<<6 | version<<3 | mode
	message[1] = stratum
	message[2] = byte(poll)
	message[3] = byte(precision)
	binary.BigEndian.PutUint32(message[4:], 0x00010000) // root delay 1s
	binary.BigEndian.PutUint32(message[8:], 0x00008000) // root dispersion 0.5s
	copy(message[12:16], refID)
	for i, value := range timestamps {
		binary.BigEndian.PutUint64(message[16+i*8:], value)
	}
	return message
}

// ntpAt is a timestamp 3925854410.25 seconds into the NTP era, which is
// 2024-05-28T03:06:50Z.
const ntpAt = uint64(3925854410)<<32 | 0x40000000

func TestNTPSummaryLineMatchesTcpdump(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		length  int
		want    string
	}{
		{"client request", ntpMessage(0, 4, 3, 0, 6, -20, nil, [4]uint64{}), 48, "NTPv4, Client, length 48"},
		{"server reply", ntpMessage(0, 4, 4, 2, 6, -23, nil, [4]uint64{}), 48, "NTPv4, Server, length 48"},
		{"symmetric active", ntpMessage(0, 4, 1, 2, 6, -20, nil, [4]uint64{}), 48, "NTPv4, symmetric active, length 48"},
		{"symmetric passive", ntpMessage(0, 4, 2, 2, 6, -20, nil, [4]uint64{}), 48, "NTPv4, symmetric passive, length 48"},
		{"broadcast", ntpMessage(0, 4, 5, 3, 6, -20, nil, [4]uint64{}), 48, "NTPv4, Broadcast, length 48"},
		{"control message", ntpMessage(0, 4, 6, 0, 0, 0, nil, [4]uint64{}), 48, "NTPv4, Control Message, length 48"},
		{"reserved mode", ntpMessage(0, 4, 7, 0, 0, 0, nil, [4]uint64{}), 48, "NTPv4, Reserved, length 48"},
		{"version 3", ntpMessage(0, 3, 4, 2, 6, -20, nil, [4]uint64{}), 48, "NTPv3, Server, length 48"},
		// The version and mode come from the first byte alone, so tcpdump names
		// them even when nothing else survived.
		{"short message", []byte{0x23, 0x00}, 2, "NTPv4, Client, length 2"},
		{"all-zero payload", make([]byte, 40), 40, "NTPv0, unspecified, length 40"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ntpSummary(tc.payload, tc.length, 0); got != tc.want {
				t.Fatalf("ntpSummary = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNTPVerboseBodyMatchesTcpdump(t *testing.T) {
	payload := ntpMessage(0, 4, 4, 2, 6, -23, []byte{192, 168, 1, 1}, [4]uint64{ntpAt, ntpAt, ntpAt, ntpAt})
	want := strings.Join([]string{
		"NTPv4, Server, length 48",
		"\tLeap indicator:  (0), Stratum 2 (secondary reference), poll 6 (64s), precision -23",
		"\tRoot Delay: 1.000000, Root dispersion: 0.500000, Reference-ID: 0xc0a80101",
		"\t  Reference Timestamp:  3925854410.250000000 (2024-05-28T03:06:50Z)",
		"\t  Originator Timestamp: 3925854410.250000000 (2024-05-28T03:06:50Z)",
		"\t  Receive Timestamp:    3925854410.250000000 (2024-05-28T03:06:50Z)",
		"\t  Transmit Timestamp:   3925854410.250000000 (2024-05-28T03:06:50Z)",
		// An originator equal to the other timestamp comes out as negative zero.
		"\t    Originator - Receive Timestamp:  -0.000000000",
		"\t    Originator - Transmit Timestamp: -0.000000000",
	}, "\n")
	if got := ntpSummary(payload, 48, 1); got != want {
		t.Fatalf("ntpSummary =\n%s\nwant\n%s", got, want)
	}
}

func TestNTPZeroOriginatorPrintsTheOtherTimestamp(t *testing.T) {
	// tcpdump has no delta to take from a zero originator, so it prints the
	// other timestamp outright, wall-clock suffix and all.
	payload := ntpMessage(0, 4, 3, 0, 6, -20, nil, [4]uint64{0, 0, 0, ntpAt})
	got := ntpSummary(payload, 48, 1)
	for _, want := range []string{
		"\t  Originator Timestamp: 0.000000000",
		"\t    Originator - Receive Timestamp:  0.000000000",
		"\t    Originator - Transmit Timestamp: 3925854410.250000000 (2024-05-28T03:06:50Z)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}
}

func TestNTPDeltaSigns(t *testing.T) {
	const later = uint64(3925854420)<<32 | 0x80000000
	cases := []struct {
		name          string
		origin, other uint64
		want          string
	}{
		{"originator ahead", later, ntpAt, "-10.250000000"},
		{"originator behind", ntpAt, later, "+10.250000000"},
		{"equal", ntpAt, ntpAt, "-0.000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ntpTimestampDelta(tc.origin, tc.other); got != tc.want {
				t.Fatalf("ntpTimestampDelta = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNTPTruncatedMessageIsMarkedInvalid(t *testing.T) {
	// 47 bytes is one short of the header, and tcpdump prints the leap
	// indicator it already read before giving up on the rest.
	payload := ntpMessage(0, 4, 4, 2, 6, -20, nil, [4]uint64{})[:47]
	want := "NTPv4, Server, length 47\n\tLeap indicator:  (0) (invalid)"
	if got := ntpSummary(payload, 47, 1); got != want {
		t.Fatalf("ntpSummary = %q, want %q", got, want)
	}
}

func TestNTPLeapIndicatorNames(t *testing.T) {
	// The printed number is the raw two-bit field left in place, not its value.
	cases := []struct {
		leap uint8
		want string
	}{
		{0, "\tLeap indicator:  (0),"},
		{1, "\tLeap indicator: +1s (64),"},
		{2, "\tLeap indicator: -1s (128),"},
		{3, "\tLeap indicator: clock unsynchronized (192),"},
	}
	for _, tc := range cases {
		payload := ntpMessage(tc.leap, 4, 4, 2, 6, -20, nil, [4]uint64{})
		if got := ntpSummary(payload, 48, 1); !strings.Contains(got, tc.want) {
			t.Errorf("leap %d output is missing %q:\n%s", tc.leap, tc.want, got)
		}
	}
}

func TestNTPStratumAndReferenceID(t *testing.T) {
	cases := []struct {
		name    string
		stratum uint8
		refID   []byte
		want    string
	}{
		{"unspecified ignores the identifier", 0, []byte("RATE"), "Stratum 0 (unspecified), poll 6 (64s), precision -20"},
		{"unspecified reference", 0, []byte("RATE"), "Reference-ID: (unspec)"},
		{"primary reference prints the clock id", 1, []byte("GPS "), "Reference-ID: GPS "},
		{"unprintable clock id is escaped", 1, []byte{1, 2, 3, 4}, "Reference-ID: ^A^B^C^D"},
		{"high bytes use meta notation", 1, []byte{0x7e, 0x7f, 0x80, 0xff}, "Reference-ID: ~^?M-^@M-^?"},
		{"secondary reference is opaque", 2, []byte{1, 2, 3, 4}, "Reference-ID: 0x01020304"},
		{"stratum 15 is still secondary", 15, []byte{1, 2, 3, 4}, "Stratum 15 (secondary reference)"},
		{"stratum 16 is reserved", 16, []byte{1, 2, 3, 4}, "Stratum 16 (reserved)"},
		{"stratum 255 is reserved", 255, []byte{1, 2, 3, 4}, "Stratum 255 (reserved)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := ntpMessage(0, 4, 4, tc.stratum, 6, -20, tc.refID, [4]uint64{})
			if got := ntpSummary(payload, 48, 1); !strings.Contains(got, tc.want) {
				t.Fatalf("output is missing %q:\n%s", tc.want, got)
			}
		})
	}
}

func TestNTPPollInterval(t *testing.T) {
	// Beyond a magnitude of 31 the shift would overflow and tcpdump prints the
	// bare number.
	cases := []struct {
		poll int8
		want string
	}{
		{0, " (1s)"},
		{4, " (16s)"},
		{10, " (1024s)"},
		{31, " (2147483648s)"},
		{32, ""},
		{127, ""},
		{-1, " (1/2s)"},
		{-3, " (1/8s)"},
		{-31, " (1/2147483648s)"},
		{-32, ""},
		{-128, ""},
	}
	for _, tc := range cases {
		if got := ntpPollInterval(tc.poll); got != tc.want {
			t.Errorf("ntpPollInterval(%d) = %q, want %q", tc.poll, got, tc.want)
		}
	}
}

func TestNTPTrailingBytes(t *testing.T) {
	base := ntpMessage(0, 4, 4, 2, 6, -20, []byte{1, 2, 3, 4}, [4]uint64{})
	withExtra := func(extra int) []byte {
		message := append(append([]byte{}, base...), make([]byte, extra)...)
		binary.BigEndian.PutUint32(message[48:], 7)
		for i := 52; i < len(message); i++ {
			message[i] = byte(i)
		}
		return message
	}
	cases := []struct {
		name  string
		extra int
		want  string
	}{
		{"key id only", 4, "\tKey id: 7"},
		{"key id and 128-bit digest", 20, "\tAuthentication: 3435363738393a3b3c3d3e3f40414243"},
		{"key id and 160-bit digest", 24, "\tAuthentication: 3435363738393a3b3c3d3e3f4041424344454647"},
		{"an unrecognised tail is only counted", 12, "\t(12 more bytes after the header)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := withExtra(tc.extra)
			if got := ntpSummary(payload, len(payload), 1); !strings.Contains(got, tc.want) {
				t.Fatalf("output is missing %q:\n%s", tc.want, got)
			}
		})
	}
}

// ntpControlMessage builds a mode-6 control message with dataLen bytes of
// payload after the fixed 12-byte header.
func ntpControlMessage(flags byte, sequence, status, assoc, offset, count uint16, dataLen int) []byte {
	message := make([]byte, ntpControlHeaderLen+dataLen)
	message[0] = 4<<3 | ntpModeControl
	message[1] = flags
	binary.BigEndian.PutUint16(message[2:], sequence)
	binary.BigEndian.PutUint16(message[4:], status)
	binary.BigEndian.PutUint16(message[6:], assoc)
	binary.BigEndian.PutUint16(message[8:], offset)
	binary.BigEndian.PutUint16(message[10:], count)
	return message
}

func TestNTPControlMessageMatchesTcpdump(t *testing.T) {
	cases := []struct {
		name    string
		message []byte
		want    string
	}{
		{
			"request",
			ntpControlMessage(0x02, 1772, 0, 0, 0, 0, 0),
			"\tLeap indicator:  (0), Request, OK, Last, OpCode=2\n\tSequence=1772, Status=0, Assoc.=0, Offset=0, Count=0",
		},
		{
			// C's %#x leaves a zero bare rather than writing 0x0.
			"response carries a status word",
			ntpControlMessage(0x82, 1772, 0x0615, 1, 0, 0, 0),
			"\tLeap indicator:  (0), Response, OK, Last, OpCode=2\n\tSequence=1772, Status=0x615, Assoc.=1, Offset=0, Count=0",
		},
		{
			"error and more bits",
			ntpControlMessage(0xE2, 1772, 0, 0, 0, 0, 0),
			"\tLeap indicator:  (0), Response, Error, More, OpCode=2\n\tSequence=1772, Status=0, Assoc.=0, Offset=0, Count=0",
		},
		{
			"data present is acknowledged but not decoded",
			ntpControlMessage(0x02, 1, 0, 0, 0, 8, 8),
			"\tLeap indicator:  (0), Request, OK, Last, OpCode=2\n\tSequence=1, Status=0, Assoc.=0, Offset=0, Count=8\n\tTO-BE-DONE: data not interpreted",
		},
		{
			"a count larger than the payload is invalid",
			ntpControlMessage(0x02, 1, 0, 0, 0, 4096, 8),
			"\tLeap indicator:  (0), Request, OK, Last, OpCode=2\n\tSequence=1, Status=0, Assoc.=0, Offset=0, Count=4096 (invalid)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := fmt.Sprintf("NTPv4, Control Message, length %d\n%s", len(tc.message), tc.want)
			if got := ntpSummary(tc.message, len(tc.message), 1); got != want {
				t.Fatalf("ntpSummary =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestNTPControlMessageTruncated(t *testing.T) {
	// Anything short of the 12-byte control header leaves tcpdump with only
	// the leap indicator it already read.
	message := ntpControlMessage(0x02, 7, 0, 0, 0, 0, 0)[:11]
	want := "NTPv4, Control Message, length 11\n\tLeap indicator:  (0) (invalid)"
	if got := ntpSummary(message, 11, 1); got != want {
		t.Fatalf("ntpSummary = %q, want %q", got, want)
	}
}

func TestNTPPrivateModeStopsAtTheLeapIndicator(t *testing.T) {
	private := ntpMessage(0, 4, 7, 0, 0, 0, nil, [4]uint64{})
	if got := ntpSummary(private, 48, 1); got != "NTPv4, Reserved, length 48\n\tLeap indicator:  (0)" {
		t.Fatalf("private message = %q", got)
	}
}

func TestNTPEmptyPayloadPrintsTheTruncationMarker(t *testing.T) {
	if got := ntpSummary(nil, 0, 0); !strings.Contains(got, "[|ntp]") {
		t.Fatalf("empty payload = %q", got)
	}
}
