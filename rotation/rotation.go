// Package rotation implements pcap file writing with size- and time-based
// rotation (PcapWriter).
package rotation

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PcapWriter writes packets to a pcap file with optional size- and time-based
// rotation. When rotation triggers, the current file is closed and a new one
// is opened with a numeric suffix (e.g. capture_001.pcap).
type PcapWriter struct {
	baseFile   string
	snaplen    uint32
	linkType   layers.LinkType
	rotateSize uint64
	rotateTime uint64

	file         *os.File
	buf          *bufio.Writer
	writer       *pcapgo.Writer
	bytesWritten uint64
	startTime    time.Time
	fileIdx      int
}

// NewPcapWriter creates a PcapWriter for baseFile. rotateSize triggers rotation
// after that many bytes (0 = disabled); rotateTime triggers rotation after that
// many seconds (0 = disabled). Call Open before writing any packets.
func NewPcapWriter(baseFile string, snaplen uint32, lt layers.LinkType, rotateSize, rotateTime uint64) *PcapWriter {
	return &PcapWriter{
		baseFile:   baseFile,
		snaplen:    snaplen,
		linkType:   lt,
		rotateSize: rotateSize,
		rotateTime: rotateTime,
	}
}

// Filename returns the path of the current output file. For the first segment
// it returns baseFile unchanged; subsequent segments get a _NNN suffix.
func (pw *PcapWriter) Filename() string {
	if pw.fileIdx == 0 {
		return pw.baseFile
	}
	dot := strings.LastIndex(pw.baseFile, ".")
	if dot != -1 {
		return fmt.Sprintf("%s_%03d%s", pw.baseFile[:dot], pw.fileIdx, pw.baseFile[dot:])
	}
	return fmt.Sprintf("%s_%03d", pw.baseFile, pw.fileIdx)
}

// Open creates the current output file and writes the pcap global header.
// It is a no-op when baseFile is empty.
func (pw *PcapWriter) Open() {
	if pw.baseFile == "" {
		return
	}
	fname := pw.Filename()
	f, err := os.Create(fname) //nolint:gosec // fname comes from the -w flag
	if err != nil {
		log.Fatalf("cannot create pcap file: %v", err)
	}
	pw.file = f
	pw.buf = bufio.NewWriterSize(f, 1024*1024)
	pw.writer = pcapgo.NewWriter(pw.buf)
	if err := pw.writer.WriteFileHeader(pw.snaplen, pw.linkType); err != nil {
		log.Fatalf("write pcap file header: %v", err)
	}
	pw.bytesWritten = 24
	pw.startTime = time.Now()
}

// Close flushes and closes the current output file.
func (pw *PcapWriter) Close() {
	if pw.file != nil {
		if pw.buf != nil {
			if err := pw.buf.Flush(); err != nil {
				log.Printf("flush pcap buffer: %v", err)
			}
			pw.buf = nil
		}
		if err := pw.file.Close(); err != nil {
			log.Printf("close pcap file: %v", err)
		}
		pw.file = nil
		pw.writer = nil
	}
}

// WritePacket appends a packet to the current output file, rotating if
// the configured size or time limit has been reached.
func (pw *PcapWriter) WritePacket(ts time.Time, data []byte) {
	if pw.writer == nil {
		return
	}
	needRotate := (pw.rotateSize > 0 && pw.bytesWritten+uint64(len(data))+16 >= pw.rotateSize) ||
		(pw.rotateTime > 0 && uint64(time.Since(pw.startTime).Seconds()) >= pw.rotateTime)
	if needRotate {
		pw.Close()
		pw.fileIdx++
		pw.Open()
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}
	if err := pw.writer.WritePacket(ci, data); err != nil {
		log.Printf("write packet: %v", err)
		return
	}
	pw.bytesWritten += uint64(16 + len(data))
}
