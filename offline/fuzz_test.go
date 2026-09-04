package offline_test

import (
	"bytes"
	"compress/gzip"
	"strings"
	"tcpdump_go/offline"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// maxFuzzRecords bounds a single input so a crafted file that decodes into a
// huge number of records cannot hang the fuzzer instead of failing it.
const maxFuzzRecords = 512

// FuzzReader drives the parser the way the CLI does: open an untrusted stream,
// read every record, and decode it. Reading a capture is the one place where
// this tool consumes bytes it did not produce, so it must not panic, and
// ReadPacketData must not hand out a slice that disagrees with its CaptureInfo.
func FuzzReader(f *testing.F) {
	f.Add(classicSeed(f))
	f.Add(pcapngSeed(f))
	f.Add(gzipSeed(f))
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x0d, 0x0d, 0x0a})             // pcapng magic, nothing else
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1})             // classic magic, truncated header
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00}) // gzip magic, truncated body

	f.Fuzz(func(t *testing.T, data []byte) {
		reader, err := offline.OpenReader(bytes.NewReader(data), "fuzz")
		if err != nil {
			return
		}
		defer func() {
			// A malformed stream may legitimately report a trailing error, such
			// as a truncated gzip trailer. Close still has to be panic-free and
			// idempotent so the CLI's deferred close cannot double-fail.
			_ = reader.Close()
			if err := reader.Close(); err != nil {
				t.Fatalf("second Close returned %v, want nil", err)
			}
		}()

		for range maxFuzzRecords {
			packet, captureInfo, linkType, err := reader.ReadPacketData()
			if err != nil {
				return
			}
			if captureInfo.CaptureLength != len(packet) {
				t.Fatalf("CaptureLength %d does not match %d returned bytes", captureInfo.CaptureLength, len(packet))
			}
			if captureInfo.Length < captureInfo.CaptureLength {
				t.Fatalf("wire length %d is below capture length %d", captureInfo.Length, captureInfo.CaptureLength)
			}
			// Decoding is part of the untrusted path: -r feeds these bytes
			// straight into the layer decoders.
			gopacket.NewPacket(packet, linkType, gopacket.DecodeOptions{Lazy: false, NoCopy: true})
		}
	})
}

// A crafted if_tsresol option makes gopacket v1.7.1 divide by zero while
// reading an interface descriptor. Found by FuzzReader; the reader has to turn
// that into an error, because -r is pointed at files from anywhere.
func TestHostileTimestampResolutionDoesNotPanic(t *testing.T) {
	hostile := []byte("\n\r\r\nD\x00\x00\x00M<+\x1a\x01\x00\x00\x000000000000 \x00" +
		"0000000000000000000000000000000000\x00\x000000\x01\x00\x00\x000\x00\x00\x00" +
		"0000000000\x05\x000000000000\x06\x00A0000000\t\x00\x00\x00000000000000")

	reader, err := offline.OpenReader(bytes.NewReader(hostile), "hostile.pcapng")
	if err != nil {
		return // rejected at open time is an equally good outcome
	}
	defer func() { _ = reader.Close() }()

	_, _, _, err = reader.ReadPacketData()
	if err == nil {
		t.Fatal("ReadPacketData accepted a capture with an out-of-range if_tsresol")
	}
	if !strings.Contains(err.Error(), "malformed capture") {
		t.Fatalf("error = %v, want it to report a malformed capture", err)
	}
}

func classicSeed(f *testing.F) []byte {
	f.Helper()
	var buffer bytes.Buffer
	writer := pcapgo.NewWriterNanos(&buffer)
	if err := writer.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
		f.Fatal(err)
	}
	payload := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
		10, 0, 0, 1, 10, 0, 0, 2,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(payload), Length: len(payload)}
	if err := writer.WritePacket(ci, payload); err != nil {
		f.Fatal(err)
	}
	return buffer.Bytes()
}

func pcapngSeed(f *testing.F) []byte {
	f.Helper()
	var buffer bytes.Buffer
	intf := pcapgo.DefaultNgInterface
	intf.LinkType = layers.LinkTypeEthernet
	intf.SnapLength = 262144
	writer, err := pcapgo.NewNgWriterInterface(&buffer, intf, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		f.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xff}, 20)
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(2, 0), CaptureLength: len(payload), Length: len(payload)}
	if err := writer.WritePacket(ci, payload); err != nil {
		f.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		f.Fatal(err)
	}
	return buffer.Bytes()
}

func gzipSeed(f *testing.F) []byte {
	f.Helper()
	var buffer bytes.Buffer
	compressor := gzip.NewWriter(&buffer)
	if _, err := compressor.Write(classicSeed(f)); err != nil {
		f.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		f.Fatal(err)
	}
	return buffer.Bytes()
}
