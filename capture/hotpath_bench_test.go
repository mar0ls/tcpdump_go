package capture

import (
	"errors"
	"io"
	"os"
	"tcpdump_go/stats"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

// These benchmarks record why runRawWritePipeline exists and why it is
// single-threaded. They replay a capture file so the comparison needs neither
// root nor a live interface:
//
//	BENCH_PCAP=/tmp/big.pcap go test ./capture -run '^$' -bench Write -benchtime 3x
//
// On an M4 with a 2M-packet file: decoding 1.24s, no statistics 0.62s, raw
// 0.35s, raw through a copying queue 0.66s. Handing packets to a writer
// goroutine costs about as much as the decoding the fast path removes, which
// is why the raw path writes inline.
func benchPcap(tb testing.TB) string {
	tb.Helper()
	path := os.Getenv("BENCH_PCAP")
	if path == "" {
		tb.Skip("set BENCH_PCAP to a capture file to run the hot-path benchmarks")
	}
	return path
}

func benchSource(b *testing.B, path string) (*pcap.Handle, *pcapgo.Writer) {
	b.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		b.Fatal(err)
	}
	writer := pcapgo.NewWriter(io.Discard)
	if err := writer.WriteFileHeader(defaultSnaplen, handle.LinkType()); err != nil {
		b.Fatal(err)
	}
	return handle, writer
}

// BenchmarkWriteDecoding is the path taken when something needs decoded
// packets: a gopacket.Packet per packet plus the statistics counters.
func BenchmarkWriteDecoding(b *testing.B) {
	path := benchPcap(b)
	for range b.N {
		handle, writer := benchSource(b, path)
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		source.Lazy = true
		source.NoCopy = true
		session := stats.NewStats()
		for {
			packet, err := source.NextPacket()
			if err != nil {
				break
			}
			session.Update(packet)
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				b.Fatal(err)
			}
		}
		handle.Close()
	}
}

// BenchmarkWriteNoStatistics keeps the gopacket.Packet but never looks inside
// it, isolating the cost of the statistics counters from the cost of building
// the packet at all.
func BenchmarkWriteNoStatistics(b *testing.B) {
	path := benchPcap(b)
	for range b.N {
		handle, writer := benchSource(b, path)
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		source.Lazy = true
		source.NoCopy = true
		for {
			packet, err := source.NextPacket()
			if err != nil {
				break
			}
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				b.Fatal(err)
			}
		}
		handle.Close()
	}
}

// BenchmarkWriteRaw is what runRawWritePipeline does.
func BenchmarkWriteRaw(b *testing.B) {
	path := benchPcap(b)
	for range b.N {
		handle, writer := benchSource(b, path)
		var captured uint64
		// A replayed file ends in EOF, which the live pipeline reports as an
		// error because a live capture must not end on its own.
		err := runRawWritePipeline(b.Context(), handle, 0, writer.WritePacket, nil, false, &captured)
		if err != nil && !errors.Is(err, io.EOF) {
			b.Fatal(err)
		}
		handle.Close()
	}
}

// BenchmarkWriteRawQueued is the rejected alternative: the zero-copy buffer is
// only valid until the next read, so decoupling the writer means copying every
// packet into a pooled buffer and paying for a channel handoff.
func BenchmarkWriteRawQueued(b *testing.B) {
	path := benchPcap(b)
	type queued struct {
		ci   gopacket.CaptureInfo
		data []byte
	}
	for range b.N {
		handle, writer := benchSource(b, path)
		pending := make(chan queued, 4096)
		recycled := make(chan []byte, 4096)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for item := range pending {
				if err := writer.WritePacket(item.ci, item.data); err != nil {
					return
				}
				select {
				case recycled <- item.data[:0]:
				default:
				}
			}
		}()
		for {
			data, ci, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				break
			}
			var buf []byte
			select {
			case buf = <-recycled:
			default:
				buf = make([]byte, 0, 2048)
			}
			pending <- queued{ci: ci, data: append(buf, data...)}
		}
		close(pending)
		<-done
		handle.Close()
	}
}
