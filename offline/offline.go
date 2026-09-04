// Package offline provides lossless, explicit-error pcap and pcapng I/O.
package offline

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	pcapngMagic = [4]byte{0x0a, 0x0d, 0x0d, 0x0a}
	gzipMagic   = [2]byte{0x1f, 0x8b}
)

type packetDataReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// Reader reads classic pcap and pcapng, including gzip-compressed streams.
// For pcapng it preserves every interface/link type instead of silently
// skipping packets whose type differs from the first interface.
type Reader struct {
	source     packetDataReader
	pcapReader *pcapgo.Reader
	ngReader   *pcapgo.NgReader
	file       *os.File
	gzip       *gzip.Reader
	path       string
}

// Open opens path. A path of "-" reads from stdin without closing it.
func Open(path string) (*Reader, error) {
	var (
		input io.Reader = os.Stdin
		file  *os.File
	)
	if path == "" {
		return nil, errors.New("capture input path is empty")
	}
	if path != "-" {
		var err error
		file, err = os.Open(path) //nolint:gosec // path is provided by the CLI caller
		if err != nil {
			return nil, fmt.Errorf("open capture %q: %w", path, err)
		}
		input = file
	}
	return newReader(input, file, path)
}

// OpenReader reads a capture from an already-open stream. name only labels
// error messages; the stream is not closed by Close.
func OpenReader(input io.Reader, name string) (*Reader, error) {
	if input == nil {
		return nil, errors.New("capture input stream is nil")
	}
	return newReader(input, nil, name)
}

// malformedCapture wraps a panic raised inside the third-party parser.
// gopacket v1.7.1 divides by zero on a crafted if_tsresol option (pcapgo
// ngread.go readInterfaceDescriptor), so reading a hostile file must fail
// rather than crash the process.
func malformedCapture(recovered any) error {
	return fmt.Errorf("malformed capture: %v", recovered)
}

func newReader(input io.Reader, file *os.File, path string) (result *Reader, retErr error) {
	reader := &Reader{file: file, path: path}
	fail := func(err error) (*Reader, error) {
		return nil, errors.Join(err, reader.Close())
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result, retErr = fail(fmt.Errorf("open capture %q: %w", path, malformedCapture(recovered)))
		}
	}()
	buffered := bufio.NewReader(input)
	firstTwo, err := buffered.Peek(2)
	if err != nil {
		return fail(fmt.Errorf("read capture header from %q: %w", path, normalizeShortRead(err)))
	}
	var content *bufio.Reader
	if [2]byte(firstTwo) == gzipMagic {
		reader.gzip, err = gzip.NewReader(buffered)
		if err != nil {
			return fail(fmt.Errorf("open gzip capture %q: %w", path, err))
		}
		content = bufio.NewReader(reader.gzip)
	} else {
		content = buffered
	}

	magic, err := content.Peek(4)
	if err != nil {
		return fail(fmt.Errorf("read capture header from %q: %w", path, normalizeShortRead(err)))
	}
	if [4]byte(magic) == pcapngMagic {
		ng, err := pcapgo.NewNgReader(content, pcapgo.NgReaderOptions{
			WantMixedLinkType:  true,
			SkipUnknownVersion: true,
		})
		if err != nil {
			return fail(fmt.Errorf("open pcapng %q: %w", path, err))
		}
		reader.source = ng
		reader.ngReader = ng
		return reader, nil
	}

	classic, err := pcapgo.NewReader(content)
	if err != nil {
		return fail(fmt.Errorf("open pcap %q: %w", path, err))
	}
	reader.source = classic
	reader.pcapReader = classic
	return reader, nil
}

func normalizeShortRead(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Close closes decompression and file resources. stdin is never closed.
func (r *Reader) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.gzip != nil {
		if err := r.gzip.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close gzip capture %q: %w", r.path, err))
		}
		r.gzip = nil
	}
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close capture %q: %w", r.path, err))
		}
		r.file = nil
	}
	return errors.Join(errs...)
}

// ReadPacketData reads one record and reports the record's actual link type.
// io.EOF means clean end-of-file; io.ErrUnexpectedEOF and all other errors
// indicate a malformed or failed input and must not be treated as success.
func (r *Reader) ReadPacketData() (packet []byte, info gopacket.CaptureInfo, link layers.LinkType, retErr error) {
	if r == nil || r.source == nil {
		return nil, gopacket.CaptureInfo{}, 0, errors.New("capture reader is not open")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			packet, link, retErr = nil, 0, malformedCapture(recovered)
		}
	}()
	data, ci, err := r.source.ReadPacketData()
	if err != nil {
		return nil, ci, 0, err
	}
	if ci.CaptureLength != len(data) {
		return nil, ci, 0, fmt.Errorf("record capture length %d does not match %d data bytes", ci.CaptureLength, len(data))
	}
	if ci.Length < ci.CaptureLength {
		return nil, ci, 0, fmt.Errorf("record wire length %d is smaller than capture length %d", ci.Length, ci.CaptureLength)
	}

	if r.pcapReader != nil {
		return data, ci, r.pcapReader.LinkType(), nil
	}
	if len(ci.AncillaryData) != 1 {
		return nil, ci, 0, fmt.Errorf("pcapng packet has no link-type metadata")
	}
	linkType, ok := ci.AncillaryData[0].(layers.LinkType)
	if !ok {
		return nil, ci, 0, fmt.Errorf("pcapng packet has invalid link-type metadata %T", ci.AncillaryData[0])
	}
	return data, ci, linkType, nil
}

// IsNg reports whether the input is pcapng.
func (r *Reader) IsNg() bool { return r != nil && r.ngReader != nil }

// LinkType returns the classic pcap link type. For mixed pcapng, callers must
// use the per-packet value returned by ReadPacketData.
func (r *Reader) LinkType() layers.LinkType {
	if r != nil && r.pcapReader != nil {
		return r.pcapReader.LinkType()
	}
	return 0
}

// Snaplen returns the classic pcap header snap length. pcapng can have one
// value per interface, so zero is returned and callers should choose a safe
// value from the packets they write.
func (r *Reader) Snaplen() uint32 {
	if r != nil && r.pcapReader != nil {
		return r.pcapReader.Snaplen()
	}
	return 0
}

// PacketSnaplen returns the header/interface snap length applicable to ci.
func (r *Reader) PacketSnaplen(ci gopacket.CaptureInfo) uint32 {
	if r == nil {
		return 0
	}
	if r.pcapReader != nil {
		return r.pcapReader.Snaplen()
	}
	if r.ngReader != nil {
		if intf, err := r.ngReader.Interface(ci.InterfaceIndex); err == nil {
			return intf.SnapLength
		}
	}
	return 0
}

// Interface returns metadata for the current pcapng section/interface.
func (r *Reader) Interface(index int) (pcapgo.NgInterface, error) {
	if r == nil || r.ngReader == nil {
		return pcapgo.NgInterface{}, errors.New("capture is not pcapng")
	}
	return r.ngReader.Interface(index)
}
