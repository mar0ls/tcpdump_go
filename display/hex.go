package display

import (
	"sync"

	"github.com/google/gopacket"
)

const hexTable = "0123456789abcdef"

var hexBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 128)
		return &buf
	},
}

// AppendOffset appends a 4-digit zero-padded hex offset to buf and returns the result.
func AppendOffset(buf []byte, i int) []byte {
	return append(buf,
		hexTable[(i>>12)&0xf],
		hexTable[(i>>8)&0xf],
		hexTable[(i>>4)&0xf],
		hexTable[i&0xf],
	)
}

// PrintHex prints data as a hex dump (without ASCII column) to Out.
// Each row shows a 4-hex-digit offset followed by up to 16 bytes in hex.
func PrintHex(data []byte) {
	bufPtr := hexBufPool.Get().(*[]byte)
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
		_, _ = Out.Write(buf)
		*bufPtr = buf
	}
	hexBufPool.Put(bufPtr)
}

// PrintHexASCII prints data as a hex+ASCII dump to Out (tcpdump -X style).
// Each row shows offset, hex bytes, and a printable-ASCII column.
func PrintHexASCII(data []byte) {
	bufPtr := hexBufPool.Get().(*[]byte)
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
		_, _ = Out.Write(buf)
		*bufPtr = buf
	}
	hexBufPool.Put(bufPtr)
}

// PacketPayload returns the packet bytes above the link layer (i.e. the
// network layer and above). Falls back to the full raw data if no link layer
// is present.
func PacketPayload(packet gopacket.Packet) []byte {
	if ll := packet.LinkLayer(); ll != nil {
		return ll.LayerPayload()
	}
	return packet.Data()
}
