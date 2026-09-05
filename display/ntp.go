package display

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// NTP rendering follows tcpdump's ntp_print. The summary line is built from
// the first byte alone, so a truncated message still names its version and
// mode; the detailed body needs the whole 48-byte header to be present.
//
// The message is parsed here rather than through gopacket's NTP layer, which
// refuses anything shorter than the full header and so cannot reproduce
// tcpdump's "(invalid)" line.

const (
	ntpHeaderLen = 48
	// ntpEpochOffset is the gap between the NTP epoch (1900-01-01) and Unix time.
	ntpEpochOffset = 2208988800
	// ntpFractionScale is 2^32, the divisor for a 32-bit timestamp fraction.
	ntpFractionScale = 4294967296.0

	ntpModeControl = 6
	ntpModePrivate = 7

	// ntpControlHeaderLen is the fixed part of a mode-6 control message.
	ntpControlHeaderLen = 12
)

// ntpPorts is the UDP port tcpdump hands to its NTP printer.
var ntpPorts = map[uint16]bool{123: true}

var ntpModeNames = [8]string{
	"unspecified",
	"symmetric active",
	"symmetric passive",
	"Client",
	"Server",
	"Broadcast",
	"Control Message",
	"Reserved",
}

// ntpLeapNames are tcpdump's spellings. The name for "no warning" really is
// empty, which is why an ordinary message prints "Leap indicator:  (0)" with
// two spaces.
var ntpLeapNames = [4]string{"", "+1s", "-1s", "clock unsynchronized"}

// ntpSummary renders a message on the NTP port. reportedLength is the length
// tcpdump prints, taken from the UDP header rather than from the bytes that
// survived the snap length.
func ntpSummary(payload []byte, reportedLength, verbosity int) string {
	if len(payload) == 0 {
		// tcpdump reaches its truncation marker with the mode name still empty,
		// which leaves the separating space in front of it.
		return " " + Colorize("[|ntp]", ColorYellow)
	}
	leap := payload[0] >> 6
	version := (payload[0] >> 3) & 0x07
	mode := payload[0] & 0x07

	summary := fmt.Sprintf("NTPv%d, %s, length %d", version, ntpModeNames[mode], reportedLength)
	if verbosity == 0 {
		return summary
	}
	// tcpdump prints the leap indicator before it dispatches on the mode and
	// before it has checked that the rest of the message is there, so a
	// control, private-mode or truncated message still shows it.
	leapField := fmt.Sprintf("\tLeap indicator: %s (%d)", ntpLeapNames[leap], uint16(leap)<<6)
	if mode == ntpModeControl {
		return summary + "\n" + leapField + ntpControlBody(payload)
	}
	// A private-mode message gets the leap indicator and nothing else, which is
	// where tcpdump stops as well.
	if mode == ntpModePrivate {
		return summary + "\n" + leapField
	}
	if len(payload) < ntpHeaderLen {
		return summary + "\n" + leapField + " (invalid)"
	}

	stratum := payload[1]
	poll := int8(payload[2])      //nolint:gosec // the poll interval is a signed 8-bit field
	precision := int8(payload[3]) //nolint:gosec // the precision is a signed 8-bit field
	origin := binary.BigEndian.Uint64(payload[24:32])

	var b strings.Builder
	b.WriteString(summary)
	fmt.Fprintf(&b, "\n%s, Stratum %d (%s), poll %d%s, precision %d",
		leapField, stratum, ntpStratumName(stratum), poll, ntpPollInterval(poll), precision)
	fmt.Fprintf(&b, "\n\tRoot Delay: %s, Root dispersion: %s, Reference-ID: %s",
		ntpShortFixed(binary.BigEndian.Uint32(payload[4:8])),
		ntpShortFixed(binary.BigEndian.Uint32(payload[8:12])),
		ntpReferenceID(stratum, payload[12:16]))
	fmt.Fprintf(&b, "\n\t  Reference Timestamp:  %s", ntpTimestamp(binary.BigEndian.Uint64(payload[16:24])))
	fmt.Fprintf(&b, "\n\t  Originator Timestamp: %s", ntpTimestamp(origin))
	fmt.Fprintf(&b, "\n\t  Receive Timestamp:    %s", ntpTimestamp(binary.BigEndian.Uint64(payload[32:40])))
	fmt.Fprintf(&b, "\n\t  Transmit Timestamp:   %s", ntpTimestamp(binary.BigEndian.Uint64(payload[40:48])))
	fmt.Fprintf(&b, "\n\t    Originator - Receive Timestamp:  %s",
		ntpTimestampDelta(origin, binary.BigEndian.Uint64(payload[32:40])))
	fmt.Fprintf(&b, "\n\t    Originator - Transmit Timestamp: %s",
		ntpTimestampDelta(origin, binary.BigEndian.Uint64(payload[40:48])))

	// Only these exact trailing sizes are an authenticated message to tcpdump:
	// a bare key id, or a key id followed by a 128- or 160-bit digest.
	// Anything else past the header is reported as a byte count.
	switch extra := reportedLength - ntpHeaderLen; {
	case extra <= 0:
	case extra == 4 && len(payload) >= 52:
		fmt.Fprintf(&b, "\n\tKey id: %d", binary.BigEndian.Uint32(payload[48:52]))
	case extra == 4+16 && len(payload) >= 68:
		fmt.Fprintf(&b, "\n\tKey id: %d", binary.BigEndian.Uint32(payload[48:52]))
		fmt.Fprintf(&b, "\n\tAuthentication: %x", payload[52:68])
	case extra == 4+20 && len(payload) >= 72:
		fmt.Fprintf(&b, "\n\tKey id: %d", binary.BigEndian.Uint32(payload[48:52]))
		fmt.Fprintf(&b, "\n\tAuthentication: %x", payload[52:72])
	default:
		fmt.Fprintf(&b, "\n\t(%d more bytes after the header)", extra)
	}
	return b.String()
}

// ntpControlBody continues the leap-indicator line with a mode-6 control
// header and the fields that follow it. tcpdump does not interpret the payload
// either, and says so in as many words.
func ntpControlBody(payload []byte) string {
	if len(payload) < ntpControlHeaderLen {
		return " (invalid)"
	}
	flags := payload[1]
	direction, outcome, continuation := "Request", "OK", "Last"
	if flags&0x80 != 0 {
		direction = "Response"
	}
	if flags&0x40 != 0 {
		outcome = "Error"
	}
	if flags&0x20 != 0 {
		continuation = "More"
	}
	count := binary.BigEndian.Uint16(payload[10:12])
	body := fmt.Sprintf(", %s, %s, %s, OpCode=%d", direction, outcome, continuation, flags&0x1f)
	body += fmt.Sprintf("\n\tSequence=%d, Status=%s, Assoc.=%d, Offset=%d, Count=%d",
		binary.BigEndian.Uint16(payload[2:4]),
		ntpControlStatus(binary.BigEndian.Uint16(payload[4:6])),
		binary.BigEndian.Uint16(payload[6:8]),
		binary.BigEndian.Uint16(payload[8:10]),
		count)
	if int(count) > len(payload)-ntpControlHeaderLen {
		return body + " (invalid)"
	}
	if count > 0 {
		body += "\n\tTO-BE-DONE: data not interpreted"
	}
	return body
}

// ntpControlStatus formats the status word the way C's %#x does, which leaves
// a zero bare instead of writing it as 0x0.
func ntpControlStatus(status uint16) string {
	if status == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", status)
}

func ntpStratumName(stratum uint8) string {
	switch {
	case stratum == 0:
		return "unspecified"
	case stratum == 1:
		return "primary reference"
	case stratum < 16:
		return "secondary reference"
	default:
		return "reserved"
	}
}

// ntpPollInterval renders the parenthesised poll interval, including the
// leading space. A magnitude of 32 or more would overflow the shift, and
// tcpdump prints nothing at all there.
func ntpPollInterval(poll int8) string {
	switch {
	case poll >= 0 && poll < 32:
		return fmt.Sprintf(" (%ds)", uint64(1)<<uint(poll))
	case poll < 0 && poll > -32:
		return fmt.Sprintf(" (1/%ds)", uint64(1)<<uint(-poll))
	default:
		return ""
	}
}

// ntpReferenceID renders the reference identifier, whose meaning depends on
// the stratum: a kiss code slot at 0, a clock identifier at 1, and an opaque
// word above that.
func ntpReferenceID(stratum uint8, id []byte) string {
	switch stratum {
	case 0:
		return "(unspec)"
	case 1:
		return ntpPrintableID(id)
	default:
		return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(id))
	}
}

// ntpPrintableID escapes a clock identifier the way tcpdump's string printer
// does: control characters as ^X, high bytes as M- followed by the same rule.
func ntpPrintableID(id []byte) string {
	var b strings.Builder
	for _, c := range id {
		if c >= 0x80 {
			b.WriteString("M-")
			c &= 0x7f
		}
		switch {
		case c == 0x7f:
			b.WriteString("^?")
		case c < 0x20:
			b.WriteByte('^')
			b.WriteByte(c + 0x40)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ntpShortFixed renders a 16.16 fixed-point field, whose fraction tcpdump
// reports as parts per million.
func ntpShortFixed(value uint32) string {
	fraction := int(float64(value&0xffff) / 65536.0 * 1000000.0)
	return fmt.Sprintf("%d.%06d", value>>16, fraction)
}

// ntpTimestamp renders a 64-bit timestamp, with the wall-clock time appended
// once the seconds are non-zero, as tcpdump does.
func ntpTimestamp(value uint64) string {
	seconds := uint32(value >> 32)
	text := fmt.Sprintf("%d.%09d", seconds, ntpNanoseconds(uint32(value))) //nolint:gosec // the low half is the fraction
	if seconds == 0 {
		return text
	}
	moment := time.Unix(int64(seconds)-ntpEpochOffset, 0).UTC()
	return text + moment.Format(" (2006-01-02T15:04:05Z)")
}

// ntpTimestampDelta renders the difference between the originator timestamp
// and a later one. tcpdump treats a zero originator as "no delta to take" and
// prints the other timestamp outright; otherwise it signs the result, and an
// exactly equal pair comes out as negative zero.
func ntpTimestampDelta(origin, other uint64) string {
	if origin == 0 {
		return ntpTimestamp(other)
	}
	//nolint:gosec // each timestamp splits into a 32-bit seconds and fraction half
	originSeconds, originFraction := uint32(origin>>32), uint32(origin)
	//nolint:gosec // same split for the timestamp being compared against
	otherSeconds, otherFraction := uint32(other>>32), uint32(other)

	var (
		negative bool
		seconds  uint32
		fraction uint32
	)
	switch {
	case otherSeconds > originSeconds:
		seconds = otherSeconds - originSeconds
		fraction = otherFraction - originFraction
		if originFraction > otherFraction {
			seconds--
		}
	case otherSeconds < originSeconds:
		negative = true
		seconds = originSeconds - otherSeconds
		fraction = originFraction - otherFraction
		if otherFraction > originFraction {
			seconds--
		}
	case otherFraction > originFraction:
		fraction = otherFraction - originFraction
	default:
		negative = true
		fraction = originFraction - otherFraction
	}
	sign := "+"
	if negative {
		sign = "-"
	}
	return fmt.Sprintf("%s%d.%09d", sign, seconds, ntpNanoseconds(fraction))
}

// ntpNanoseconds converts a 32-bit binary fraction into parts per billion.
func ntpNanoseconds(fraction uint32) uint32 {
	return uint32(float64(fraction) / ntpFractionScale * 1000000000.0)
}
