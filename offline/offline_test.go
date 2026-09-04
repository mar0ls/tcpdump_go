package offline

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestClassicReaderPreservesCaptureInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.pcap")
	wantTS := time.Unix(100, 123456789).UTC()
	writeClassicFixture(t, path, gopacket.CaptureInfo{Timestamp: wantTS, CaptureLength: 4, Length: 1500}, []byte{1, 2, 3, 4})

	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	data, ci, linkType, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{1, 2, 3, 4}) || ci.Length != 1500 || ci.CaptureLength != 4 || !ci.Timestamp.Equal(wantTS) {
		t.Fatalf("packet = (%v, %+v), metadata was not preserved", data, ci)
	}
	if linkType != layers.LinkTypeEthernet || reader.Snaplen() != 65535 {
		t.Fatalf("link/snaplen = %s/%d", linkType, reader.Snaplen())
	}
	_, _, _, err = reader.ReadPacketData()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("final error = %v, want EOF", err)
	}
}

func TestReaderRejectsTruncatedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "truncated.pcap")
	writeClassicFixture(t, path, gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: 8, Length: 8}, make([]byte, 8))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-3); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	_, _, _, err = reader.ReadPacketData()
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("truncated record error = %v, want a non-EOF failure", err)
	}
}

func TestReaderSupportsGzip(t *testing.T) {
	directory := t.TempDir()
	plain := filepath.Join(directory, "plain.pcap")
	compressed := filepath.Join(directory, "input.pcap.gz")
	writeClassicFixture(t, plain, gopacket.CaptureInfo{Timestamp: time.Unix(1, 2), CaptureLength: 1, Length: 1}, []byte{42})
	input, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(compressed)
	if err != nil {
		t.Fatal(err)
	}
	zipper := gzip.NewWriter(file)
	if _, err := zipper.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := Open(compressed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	data, _, _, err := reader.ReadPacketData()
	if err != nil || !bytes.Equal(data, []byte{42}) {
		t.Fatalf("gzip packet = %v, %v", data, err)
	}
}

func TestMixedPcapngReturnsEveryLinkType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.pcapng")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	first := pcapgo.DefaultNgInterface
	first.LinkType = layers.LinkTypeEthernet
	first.SnapLength = 65535
	writer, err := pcapgo.NewNgWriterInterface(file, first, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	second := pcapgo.DefaultNgInterface
	second.LinkType = layers.LinkTypeRaw
	second.SnapLength = 4096
	secondID, err := writer.AddInterface(second)
	if err != nil {
		t.Fatal(err)
	}
	packets := []struct {
		ci   gopacket.CaptureInfo
		data []byte
	}{
		{ci: gopacket.CaptureInfo{Timestamp: time.Unix(1, 1), CaptureLength: 2, Length: 10, InterfaceIndex: 0}, data: []byte{1, 2}},
		{ci: gopacket.CaptureInfo{Timestamp: time.Unix(2, 2), CaptureLength: 3, Length: 20, InterfaceIndex: secondID}, data: []byte{3, 4, 5}},
	}
	for _, packet := range packets {
		if err := writer.WritePacket(packet.ci, packet.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	var got []layers.LinkType
	for {
		_, _, linkType, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, linkType)
	}
	if len(got) != 2 || got[0] != layers.LinkTypeEthernet || got[1] != layers.LinkTypeRaw {
		t.Fatalf("link types = %v", got)
	}
}

func TestNgWriterPreservesMixedLinksAndWireLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pcapng")
	w := NewNgWriter(path)
	if err := w.Open(layers.LinkTypeEthernet, 65535); err != nil {
		t.Fatal(err)
	}
	wantTS := time.Unix(7, 987654321).UTC()
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: wantTS, Length: 1500}, []byte{1, 2, 3}, layers.LinkTypeEthernet, 65535); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: wantTS.Add(time.Nanosecond), Length: 99}, []byte{4}, layers.LinkTypeRaw, 4096); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	_, firstCI, firstLink, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	_, secondCI, secondLink, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if firstCI.Length != 1500 || firstCI.CaptureLength != 3 || !firstCI.Timestamp.Equal(wantTS) || firstLink != layers.LinkTypeEthernet {
		t.Fatalf("first metadata = %+v/%s", firstCI, firstLink)
	}
	if secondCI.Length != 99 || secondLink != layers.LinkTypeRaw {
		t.Fatalf("second metadata = %+v/%s", secondCI, secondLink)
	}
}

func TestNgWriterZeroTimestampMapsToEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zero.pcapng")
	writer := NewNgWriter(path)
	if err := writer.Open(layers.LinkTypeEthernet, 65535); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{Length: 1}, []byte{1}, layers.LinkTypeEthernet, 65535); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	_, captureInfo, _, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if epoch := time.Unix(0, 0).UTC(); !captureInfo.Timestamp.Equal(epoch) {
		t.Fatalf("timestamp = %v, want %v", captureInfo.Timestamp, epoch)
	}
}

func writeClassicFixture(t *testing.T, path string, ci gopacket.CaptureInfo, data []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriterNanos(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
