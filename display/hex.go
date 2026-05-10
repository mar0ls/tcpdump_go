package display

import (
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

// AppendOffset appends a 4-digit hex offset to buf.
func AppendOffset(buf []byte, i int) []byte {
	return append(buf,
		hexTable[(i>>12)&0xf],
		hexTable[(i>>8)&0xf],
		hexTable[(i>>4)&0xf],
		hexTable[i&0xf],
	)
}

// PrintHex prints data as a hex dump (-x style) to Out.
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

// PrintHexASCII prints data as hex+ASCII (-X style) to Out.
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

// PacketPayload returns packet data above the link layer.
func PacketPayload(packet gopacket.Packet) []byte {
	if ll := packet.LinkLayer(); ll != nil {
		return ll.LayerPayload()
	}
	return packet.Data()
}
