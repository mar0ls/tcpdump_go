package rotation

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestNewPcapWriter(t *testing.T) {
	pw := NewPcapWriter("out.pcap", 65535, layers.LinkTypeEthernet, 0, 0)
	if pw == nil {
		t.Fatal("nil")
	}
	if pw.baseFile != "out.pcap" {
		t.Errorf("baseFile = %q", pw.baseFile)
	}
	if pw.snaplen != 65535 {
		t.Errorf("snaplen = %d", pw.snaplen)
	}
}

func TestFilename(t *testing.T) {
	tests := []struct {
		name string
		base string
		idx  int
		want string
	}{
		{name: "base segment", base: "capture.pcap", want: "capture.pcap"},
		{name: "extension", base: "capture.pcap", idx: 1, want: "capture_001.pcap"},
		{name: "multiple dots", base: "capture.raw.pcap", idx: 12, want: "capture.raw_012.pcap"},
		{name: "no extension", base: "capture_data", idx: 1, want: "capture_data_001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pw := NewPcapWriter(tt.base, 65535, layers.LinkTypeEthernet, 0, 0)
			pw.fileIdx = tt.idx
			if got := pw.Filename(); got != tt.want {
				t.Errorf("Filename() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFilename_DotInDirectoryIsNotAnExtension(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captures.v1")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "capture")
	pw := NewPcapWriter(base, 65535, layers.LinkTypeEthernet, 0, 0)
	pw.fileIdx = 1
	if got, want := pw.Filename(), filepath.Join(dir, "capture_001"); got != want {
		t.Errorf("Filename() = %q, want %q", got, want)
	}
}

func TestOpenCloseCreatesHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat open pcap: %v", err)
	}
	if info.Size() != int64(pcapHeaderSize) {
		t.Errorf("open file size = %d, want %d", info.Size(), pcapHeaderSize)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
}

func TestWritePacketPreservesCaptureMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	wantTimestamp := time.Date(2025, 3, 2, 1, 2, 3, 456789123, time.UTC)
	data := []byte{1, 2, 3, 4}
	input := gopacket.CaptureInfo{
		Timestamp:     wantTimestamp,
		CaptureLength: 1, // normalized to the bytes actually supplied
		Length:        20,
	}
	if err := pw.WritePacket(input, data); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	packets := readPcap(t, path)
	if len(packets) != 1 {
		t.Fatalf("packets = %d, want 1", len(packets))
	}
	if got := packets[0].ci.Timestamp; !got.Equal(wantTimestamp) {
		t.Errorf("Timestamp = %v, want %v", got, wantTimestamp)
	}
	if got := packets[0].ci.CaptureLength; got != len(data) {
		t.Errorf("CaptureLength = %d, want %d", got, len(data))
	}
	if got := packets[0].ci.Length; got != input.Length {
		t.Errorf("Length = %d, want %d", got, input.Length)
	}
}

func TestWritePacketRaisesWireLengthToCaptureLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "length.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3, 4}
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(10, 0), CaptureLength: 99, Length: 2}
	if err := pw.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	packets := readPcap(t, path)
	if got := packets[0].ci.Length; got != len(data) {
		t.Errorf("Length = %d, want %d", got, len(data))
	}
}

func TestWritePacketEmptyBaseIsDisabled(t *testing.T) {
	pw := NewPcapWriter("", 65535, layers.LinkTypeEthernet, 0, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	if err := pw.WritePacket(gopacket.CaptureInfo{}, []byte{42}); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWritePacketToStdoutDoesNotCloseStdout(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writeEnd
	t.Cleanup(func() {
		os.Stdout = originalStdout
		_ = readEnd.Close()
		_ = writeEnd.Close()
	})

	pw := NewPcapWriter("-", 65535, layers.LinkTypeEthernet, 0, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3}
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(5, 6), Length: len(data)}
	if err := pw.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	marker := []byte("still-open")
	if _, err := writeEnd.Write(marker); err != nil {
		t.Fatalf("stdout was closed: %v", err)
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatal(err)
	}

	output, err := io.ReadAll(readEnd)
	if err != nil {
		t.Fatal(err)
	}
	pcapLength := int(pcapHeaderSize+pcapPacketHeaderSize) + len(data)
	if len(output) != pcapLength+len(marker) {
		t.Fatalf("stdout bytes = %d, want %d", len(output), pcapLength+len(marker))
	}
	r, err := pcapgo.NewReader(bytes.NewReader(output[:pcapLength]))
	if err != nil {
		t.Fatalf("read stdout pcap header: %v", err)
	}
	gotData, gotCI, err := r.ReadPacketData()
	if err != nil {
		t.Fatalf("read stdout packet: %v", err)
	}
	if !bytes.Equal(gotData, data) || !gotCI.Timestamp.Equal(ci.Timestamp) {
		t.Errorf("stdout packet = (%v, %v), want (%v, %v)", gotData, gotCI.Timestamp, data, ci.Timestamp)
	}
	if got := output[pcapLength:]; !bytes.Equal(got, marker) {
		t.Errorf("stdout tail = %q, want %q", got, marker)
	}
}

func TestRotationBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rot.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 120, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 80) // header + one record is exactly 120 bytes
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), Length: len(data)}
	if err := pw.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	ci.Timestamp = ci.Timestamp.Add(time.Second)
	if err := pw.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	assertPacketCounts(t, map[string]int{
		path:                               1,
		filepath.Join(dir, "rot_001.pcap"): 1,
	})
}

func TestRotationOversizedFirstPacketDoesNotCreateEmptyBase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oversized.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 40, 0)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 80)
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), Length: len(data)}
	if err := pw.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	assertPacketCounts(t, map[string]int{path: 1})
	if _, err := os.Stat(filepath.Join(dir, "oversized_001.pcap")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected rotated segment: %v", err)
	}
}

func TestRotationByPacketTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "timed.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 10)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, 9 * time.Second, 10 * time.Second} {
		data := []byte{byte(offset / time.Second)}
		ci := gopacket.CaptureInfo{Timestamp: start.Add(offset), Length: len(data)}
		if err := pw.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	assertPacketCounts(t, map[string]int{
		path:                                 2,
		filepath.Join(dir, "timed_001.pcap"): 1,
	})
}

func TestZeroTimestampMapsToEpochDeterministically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zero.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 10)
	if err := pw.Open(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := pw.WritePacket(gopacket.CaptureInfo{Length: 1}, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	packets := readPcap(t, path)
	if len(packets) != 2 {
		t.Fatalf("packets = %d, want 2", len(packets))
	}
	epoch := time.Unix(0, 0).UTC()
	for index, packet := range packets {
		if !packet.ci.Timestamp.Equal(epoch) {
			t.Errorf("packet %d timestamp = %v, want %v", index, packet.ci.Timestamp, epoch)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "zero_001.pcap")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("zero timestamps caused rotation: %v", err)
	}
}

func TestErrorsAreReturned(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "out.pcap")
		pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
		if err := pw.Open(); err == nil {
			t.Fatal("Open() error = nil")
		}
	})

	t.Run("double open", func(t *testing.T) {
		pw := NewPcapWriter(filepath.Join(t.TempDir(), "out.pcap"), 65535, layers.LinkTypeEthernet, 0, 0)
		if err := pw.Open(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pw.Close() }()
		if err := pw.Open(); err == nil {
			t.Fatal("second Open() error = nil")
		}
	})

	t.Run("write while closed", func(t *testing.T) {
		pw := NewPcapWriter(filepath.Join(t.TempDir(), "out.pcap"), 65535, layers.LinkTypeEthernet, 0, 0)
		if err := pw.WritePacket(gopacket.CaptureInfo{}, []byte{1}); err == nil {
			t.Fatal("WritePacket() error = nil")
		}
	})

	t.Run("close flush", func(t *testing.T) {
		pw := NewPcapWriter(filepath.Join(t.TempDir(), "out.pcap"), 65535, layers.LinkTypeEthernet, 0, 0)
		if err := pw.Open(); err != nil {
			t.Fatal(err)
		}
		if err := pw.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), Length: 1}, []byte{1}); err != nil {
			t.Fatal(err)
		}
		if err := pw.file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := pw.Close(); err == nil {
			t.Fatal("Close() error = nil")
		}
	})

	t.Run("stdout rotation", func(t *testing.T) {
		pw := NewPcapWriter("-", 65535, layers.LinkTypeEthernet, 1, 0)
		if err := pw.Open(); err == nil || !strings.Contains(err.Error(), "stdout") {
			t.Fatalf("Open() error = %v, want stdout rotation error", err)
		}
	})
}

type capturedPacket struct {
	data []byte
	ci   gopacket.CaptureInfo
}

func readPcap(t *testing.T, path string) []capturedPacket {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("read pcap header: %v", err)
	}
	var packets []capturedPacket
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return packets
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		packets = append(packets, capturedPacket{data: data, ci: ci})
	}
}

func assertPacketCounts(t *testing.T, want map[string]int) {
	t.Helper()
	for path, wantCount := range want {
		if got := len(readPcap(t, path)); got != wantCount {
			t.Errorf("%s: packets = %d, want %d", filepath.Base(path), got, wantCount)
		}
	}
}

// -W with -C is a rotating buffer: the segment count stays at the limit and
// the oldest file is overwritten.
func TestMaxFilesWrapsAroundWithSizeRotation(t *testing.T) {
	directory := t.TempDir()
	base := filepath.Join(directory, "cap.pcap")
	writer := NewPcapWriter(base, 262144, layers.LinkTypeEthernet, 120, 0)
	writer.SetMaxFiles(3)
	if err := writer.Open(); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 60)
	for i := range 12 {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i), 0),
			CaptureLength: len(payload),
			Length:        len(payload),
		}
		if err := writer.WritePacket(ci, payload); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(directory, "cap*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("wrote %d files, want 3: %v", len(files), files)
	}
}

// -W with -G stops the capture instead of overwriting, which callers surface
// as a clean end rather than an error.
func TestMaxFilesStopsWithTimeRotation(t *testing.T) {
	directory := t.TempDir()
	base := filepath.Join(directory, "cap.pcap")
	writer := NewPcapWriter(base, 262144, layers.LinkTypeEthernet, 0, 1)
	writer.SetMaxFiles(2)
	if err := writer.Open(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()

	payload := make([]byte, 20)
	var stopped bool
	for i := range 10 {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i)*5, 0),
			CaptureLength: len(payload),
			Length:        len(payload),
		}
		err := writer.WritePacket(ci, payload)
		if errors.Is(err, ErrFileLimitReached) {
			stopped = true
			break
		}
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	if !stopped {
		t.Fatal("time rotation never reported the file limit")
	}
	files, err := filepath.Glob(filepath.Join(directory, "cap*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("wrote %d files, want 2: %v", len(files), files)
	}
}

// Without -W the writer keeps creating segments, which is the old behaviour.
func TestNoMaxFilesKeepsRotating(t *testing.T) {
	directory := t.TempDir()
	writer := NewPcapWriter(filepath.Join(directory, "cap.pcap"), 262144, layers.LinkTypeEthernet, 120, 0)
	if err := writer.Open(); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 60)
	for i := range 8 {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(int64(i), 0), CaptureLength: len(payload), Length: len(payload)}
		if err := writer.WritePacket(ci, payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(directory, "cap*.pcap"))
	if len(files) < 4 {
		t.Fatalf("only %d files: rotation stopped unexpectedly", len(files))
	}
}
