package display

import (
	"strconv"
	"sync"

	"github.com/gopacket/gopacket"
)

const hexTable = "0123456789abcdef"

var hexBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 128)
		return &buf
	},
}

// AppendOffset appends a hexadecimal offset to buf, padded to at least four
// digits.  Unlike a fixed-width implementation it does not wrap after 64 KiB.
func AppendOffset(buf []byte, i int) []byte {
	if i < 0 {
		buf = append(buf, '-')
		// Avoid overflowing on the minimum int value.
		u := uint64(-(i + 1)) + 1 //nolint:gosec // two's-complement negation of a negative int; cannot overflow
		return appendPaddedHex(buf, u)
	}
	return appendPaddedHex(buf, uint64(i))
}

func appendPaddedHex(buf []byte, value uint64) []byte {
	digits := 1
	for n := value; n >= 16; n >>= 4 {
		digits++
	}
	for range max(0, 4-digits) {
		buf = append(buf, '0')
	}
	return strconv.AppendUint(buf, value, 16)
}

// PrintHex prints data as a hex dump (-x style) to Out.
func PrintHex(data []byte) error {
	bufPtr := hexBufPool.Get().(*[]byte)
	defer hexBufPool.Put(bufPtr)
	for i := 0; i < len(data); i += 16 {
		end := min(i+16, len(data))
		buf := (*bufPtr)[:0]
		if UseColor {
			buf = append(buf, ColorGray...)
		}
		buf = AppendOffset(buf, i)
		if UseColor {
			buf = append(buf, ColorReset...)
		}
		buf = append(buf, ' ', ' ')
		for j := i; j < end; j++ {
			buf = append(buf, hexTable[data[j]>>4], hexTable[data[j]&0xf], ' ')
		}
		buf = append(buf, '\n')
		if err := writeOutput(buf); err != nil {
			*bufPtr = buf
			return err
		}
		*bufPtr = buf
	}
	return nil
}

// PrintHexASCII prints data as hex+ASCII (-X style) to Out.
func PrintHexASCII(data []byte) error {
	bufPtr := hexBufPool.Get().(*[]byte)
	defer hexBufPool.Put(bufPtr)
	for i := 0; i < len(data); i += 16 {
		end := min(i+16, len(data))
		buf := (*bufPtr)[:0]
		if UseColor {
			buf = append(buf, ColorGray...)
		}
		buf = AppendOffset(buf, i)
		if UseColor {
			buf = append(buf, ColorReset...)
		}
		buf = append(buf, ' ', ' ')
		for j := i; j < end; j++ {
			buf = append(buf, hexTable[data[j]>>4], hexTable[data[j]&0xf], ' ')
		}
		for j := end; j < i+16; j++ {
			buf = append(buf, ' ', ' ', ' ')
		}
		buf = append(buf, ' ', '|', ' ')
		for j := i; j < end; j++ {
			b := data[j]
			switch {
			case b >= 32 && b <= 126:
				buf = append(buf, b)
			case UseColor:
				buf = append(buf, ColorGray...)
				buf = append(buf, '.')
				buf = append(buf, ColorReset...)
			default:
				buf = append(buf, '.')
			}
		}
		buf = append(buf, '\n')
		if err := writeOutput(buf); err != nil {
			*bufPtr = buf
			return err
		}
		*bufPtr = buf
	}
	return nil
}

// PrintASCII prints packet bytes in a terminal-safe ASCII form (-A style).
// Control and non-ASCII bytes become dots, and long packets are wrapped to
// keep each output line readable.
func PrintASCII(data []byte) error {
	const columns = 64
	bufPtr := hexBufPool.Get().(*[]byte)
	defer hexBufPool.Put(bufPtr)
	for i := 0; i < len(data); i += columns {
		end := min(i+columns, len(data))
		buf := (*bufPtr)[:0]
		for _, b := range data[i:end] {
			if b >= 32 && b <= 126 {
				buf = append(buf, b)
			} else {
				buf = append(buf, '.')
			}
		}
		buf = append(buf, '\n')
		if err := writeOutput(buf); err != nil {
			*bufPtr = buf
			return err
		}
		*bufPtr = buf
	}
	return nil
}

// PacketPayload returns packet data above the link layer.
func PacketPayload(packet gopacket.Packet) []byte {
	if ll := packet.LinkLayer(); ll != nil {
		return ll.LayerPayload()
	}
	return packet.Data()
}
