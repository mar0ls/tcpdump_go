package rotation

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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

func TestFilename_NoRotation(t *testing.T) {
	pw := NewPcapWriter("capture.pcap", 65535, layers.LinkTypeEthernet, 0, 0)
	if got := pw.Filename(); got != "capture.pcap" {
		t.Errorf("Filename = %q", got)
	}
}

func TestFilename_WithRotation(t *testing.T) {
	pw := NewPcapWriter("capture.pcap", 65535, layers.LinkTypeEthernet, 0, 0)
	pw.fileIdx = 1
	if got := pw.Filename(); got != "capture_001.pcap" {
		t.Errorf("Filename = %q", got)
	}
	pw.fileIdx = 12
	if got := pw.Filename(); got != "capture_012.pcap" {
		t.Errorf("Filename = %q", got)
	}
}

func TestFilename_NoDot(t *testing.T) {
	pw := NewPcapWriter("capture_data", 65535, layers.LinkTypeEthernet, 0, 0)
	pw.fileIdx = 1
	if got := pw.Filename(); got != "capture_data_001" {
		t.Errorf("Filename = %q", got)
	}
}

func TestOpenCloseCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	pw.Open()
	defer pw.Close()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("plik nie istnieje: %v", err)
	}
	pw.Close()
	info, _ := os.Stat(path)
	if info.Size() < 24 {
		t.Errorf("plik za maly: %d", info.Size())
	}
}

func TestWritePacket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	pw.Open()
	data := make([]byte, 64)
	pw.WritePacket(time.Now(), data)
	pw.WritePacket(time.Now(), data)
	pw.Close()
	f, err := os.Open(path) //nolint:gosec // path is from t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap read: %v", err)
	}
	count := 0
	for {
		_, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		count++
	}
	if count != 2 {
		t.Errorf("packets = %d, want 2", count)
	}
}

func TestWritePacket_EmptyBase(t *testing.T) {
	pw := NewPcapWriter("", 65535, layers.LinkTypeEthernet, 0, 0)
	pw.Open()
	pw.WritePacket(time.Now(), []byte{42})
	pw.Close()
}

func TestRotation_BySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rot.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 200, 0)
	pw.Open()
	data := make([]byte, 80)
	for i := 0; i < 5; i++ {
		pw.WritePacket(time.Now(), data)
	}
	pw.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "rot*.pcap"))
	if len(files) < 2 {
		t.Errorf("rotacja: %d plikow, chce >= 2", len(files))
	}
}

func TestDoubleClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "double.pcap")
	pw := NewPcapWriter(path, 65535, layers.LinkTypeEthernet, 0, 0)
	pw.Open()
	pw.WritePacket(time.Now(), []byte{1, 2, 3})
	pw.Close()
	pw.Close()
}
