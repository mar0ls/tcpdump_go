// Package rotation implements pcap file writing with size- and time-based
// rotation (PcapWriter).
package rotation

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	pcapHeaderSize       = uint64(24)
	pcapPacketHeaderSize = uint64(16)
)

// PcapWriter writes packets to a pcap file with optional size- and time-based
// rotation. A baseFile of "-" writes an unrotated pcap stream to stdout.
type PcapWriter struct {
	baseFile   string
	snaplen    uint32
	linkType   layers.LinkType
	rotateSize uint64
	rotateTime uint64
	maxFiles   uint64

	file          *os.File
	buf           *bufio.Writer
	writer        *pcapgo.Writer
	bytesWritten  uint64
	segmentStart  time.Time
	packetsInFile uint64
	fileIdx       int
}

// NewPcapWriter creates a PcapWriter; rotation by size (bytes) or time
// (seconds) is disabled when the respective value is zero.
func NewPcapWriter(baseFile string, snaplen uint32, lt layers.LinkType, rotateSize, rotateTime uint64) *PcapWriter {
	return &PcapWriter{
		baseFile:   baseFile,
		snaplen:    snaplen,
		linkType:   lt,
		rotateSize: rotateSize,
		rotateTime: rotateTime,
	}
}

// ErrFileLimitReached reports that -W's file count was reached while rotating
// on time. tcpdump ends the capture there, so callers treat it as a clean stop
// rather than a failure.
var ErrFileLimitReached = errors.New("rotation file limit reached")

// SetMaxFiles applies tcpdump's -W. With size rotation the segments form a
// rotating buffer of n files; with time rotation the capture stops once n
// files exist, which is what tcpdump does for each case.
func (pw *PcapWriter) SetMaxFiles(n uint64) {
	pw.maxFiles = n
}

// Filename returns the current file path (_NNN suffix for rotated segments).
func (pw *PcapWriter) Filename() string {
	if pw.fileIdx == 0 {
		return pw.baseFile
	}
	ext := filepath.Ext(pw.baseFile)
	stem := pw.baseFile[:len(pw.baseFile)-len(ext)]
	return fmt.Sprintf("%s_%03d%s", stem, pw.fileIdx, ext)
}

// Open creates the output file and writes its pcap header. It is a no-op when
// baseFile is empty. A baseFile of "-" writes to stdout; rotating stdout is
// rejected because a pcap stream cannot contain multiple file headers.
func (pw *PcapWriter) Open() error {
	if pw.baseFile == "" {
		return nil
	}
	if pw.writer != nil {
		return errors.New("pcap writer is already open")
	}
	if pw.baseFile == "-" && (pw.rotateSize > 0 || pw.rotateTime > 0) {
		return errors.New("pcap rotation is not supported when writing to stdout")
	}

	var (
		file *os.File
		out  = os.Stdout
	)
	if pw.baseFile != "-" {
		var err error
		file, err = os.Create(pw.Filename())
		if err != nil {
			return fmt.Errorf("create pcap file %q: %w", pw.Filename(), err)
		}
		out = file
	}

	buf := bufio.NewWriterSize(out, 1024*1024)
	writer := pcapgo.NewWriterNanos(buf)
	if err := writer.WriteFileHeader(pw.snaplen, pw.linkType); err != nil {
		return closeAfterOpenError(file, fmt.Errorf("write pcap header: %w", err))
	}
	// Flushing the small file header makes Open report device/filesystem errors
	// immediately instead of deferring them until the first rotation or Close.
	if err := buf.Flush(); err != nil {
		return closeAfterOpenError(file, fmt.Errorf("flush pcap header: %w", err))
	}

	pw.file = file
	pw.buf = buf
	pw.writer = writer
	pw.bytesWritten = pcapHeaderSize
	pw.segmentStart = time.Time{}
	pw.packetsInFile = 0
	return nil
}

func closeAfterOpenError(file *os.File, openErr error) error {
	if file == nil {
		return openErr
	}
	if err := file.Close(); err != nil {
		return errors.Join(openErr, fmt.Errorf("close pcap file after open failure: %w", err))
	}
	return openErr
}

// Close flushes and closes the current output file. stdout is flushed but is
// deliberately never closed. Close is idempotent.
func (pw *PcapWriter) Close() error {
	if pw.writer == nil {
		return nil
	}

	buf := pw.buf
	file := pw.file
	pw.file = nil
	pw.buf = nil
	pw.writer = nil
	pw.bytesWritten = 0
	pw.segmentStart = time.Time{}
	pw.packetsInFile = 0

	var errs []error
	if buf != nil {
		if err := buf.Flush(); err != nil {
			errs = append(errs, fmt.Errorf("flush pcap output: %w", err))
		}
	}
	if file != nil {
		if err := file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close pcap file: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Flush makes all currently buffered pcap records visible to the underlying
// file or stream without closing it. It implements tcpdump's -U behaviour.
func (pw *PcapWriter) Flush() error {
	if pw.baseFile == "" {
		return nil
	}
	if pw.writer == nil || pw.buf == nil {
		return errors.New("pcap writer is not open")
	}
	if err := pw.buf.Flush(); err != nil {
		return fmt.Errorf("flush pcap output: %w", err)
	}
	return nil
}

// WritePacket appends a packet, rotating the file before it when adding the
// packet would exceed a configured limit. CaptureLength is normalized to the
// actual data size and Length is raised when necessary; all other CaptureInfo
// fields, including Timestamp and the original wire Length, are preserved.
// A source record without a timestamp is mapped deterministically to the Unix
// epoch because classic pcap cannot represent an absent timestamp.
func (pw *PcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if pw.baseFile == "" {
		return nil
	}
	if pw.writer == nil {
		return errors.New("pcap writer is not open")
	}
	if uint64(len(data)) > math.MaxUint32 {
		return fmt.Errorf("packet capture length %d exceeds pcap limit", len(data))
	}

	ci.CaptureLength = len(data)
	if ci.Length < ci.CaptureLength {
		ci.Length = ci.CaptureLength
	}
	if uint64(ci.Length) > math.MaxUint32 { //nolint:gosec // ci.Length was raised to len(data) above, so it is non-negative
		return fmt.Errorf("packet wire length %d exceeds pcap limit", ci.Length)
	}
	if ci.Timestamp.IsZero() {
		ci.Timestamp = time.Unix(0, 0).UTC()
	}

	if pw.shouldRotate(ci.Timestamp, uint64(len(data))) {
		if err := pw.rotate(); err != nil {
			return err
		}
	}
	if err := pw.writer.WritePacket(ci, data); err != nil {
		return fmt.Errorf("write packet to %q: %w", pw.Filename(), err)
	}

	pw.bytesWritten += pcapPacketHeaderSize + uint64(len(data))
	pw.packetsInFile++
	if pw.segmentStart.IsZero() {
		pw.segmentStart = ci.Timestamp
	}
	return nil
}

func (pw *PcapWriter) shouldRotate(ts time.Time, dataLength uint64) bool {
	// Always place the first packet in a new segment, even if that one record is
	// larger than the configured size. This avoids a header-only base segment.
	if pw.packetsInFile == 0 {
		return false
	}
	if pw.rotateSize > 0 {
		recordSize := pcapPacketHeaderSize + dataLength
		if recordSize > math.MaxUint64-pw.bytesWritten || pw.bytesWritten+recordSize > pw.rotateSize {
			return true
		}
	}
	if pw.rotateTime > 0 && !pw.segmentStart.IsZero() {
		elapsed := ts.Sub(pw.segmentStart)
		if elapsed >= 0 && uint64(elapsed/time.Second) >= pw.rotateTime {
			return true
		}
	}
	return false
}

func (pw *PcapWriter) rotate() error {
	if err := pw.Close(); err != nil {
		return fmt.Errorf("finish pcap segment %q: %w", pw.Filename(), err)
	}
	pw.fileIdx++
	if pw.maxFiles > 0 && uint64(pw.fileIdx) >= pw.maxFiles { //nolint:gosec // fileIdx only ever grows from zero
		if pw.rotateSize == 0 && pw.rotateTime > 0 {
			return ErrFileLimitReached
		}
		pw.fileIdx = 0 // wrap around, overwriting the oldest segment
	}
	if err := pw.Open(); err != nil {
		return fmt.Errorf("open next pcap segment %q: %w", pw.Filename(), err)
	}
	return nil
}
