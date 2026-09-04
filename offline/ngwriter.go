package offline

import (
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type ngInterfaceKey struct {
	linkType layers.LinkType
	snaplen  uint32
}

// NgWriter writes pcapng while retaining per-packet wire length, timestamp,
// and differing link types. It deliberately never closes stdout.
type NgWriter struct {
	path       string
	file       *os.File
	writer     *pcapgo.NgWriter
	interfaces map[ngInterfaceKey]int
}

// NewNgWriter returns a writer for path; "-" writes to stdout. The stream is
// created by Open, not here.
func NewNgWriter(path string) *NgWriter {
	return &NgWriter{path: path}
}

// Open creates a section and its first interface.
func (w *NgWriter) Open(linkType layers.LinkType, snaplen uint32) error {
	if w.path == "" {
		return errors.New("pcapng output path is empty")
	}
	if w.writer != nil {
		return errors.New("pcapng writer is already open")
	}
	var output *os.File
	if w.path == "-" {
		output = os.Stdout
	} else {
		var err error
		output, err = os.Create(w.path)
		if err != nil {
			return fmt.Errorf("create pcapng %q: %w", w.path, err)
		}
		w.file = output
	}
	intf := pcapgo.DefaultNgInterface
	intf.LinkType = linkType
	intf.SnapLength = snaplen
	writer, err := pcapgo.NewNgWriterInterface(output, intf, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return errors.Join(fmt.Errorf("write pcapng header to %q: %w", w.path, err), w.closeFile())
	}
	if err := writer.Flush(); err != nil {
		return errors.Join(fmt.Errorf("flush pcapng header to %q: %w", w.path, err), w.closeFile())
	}
	w.writer = writer
	w.interfaces = map[ngInterfaceKey]int{{linkType: linkType, snaplen: snaplen}: 0}
	return nil
}

// WritePacket adds an interface descriptor as needed and writes one packet.
func (w *NgWriter) WritePacket(ci gopacket.CaptureInfo, data []byte, linkType layers.LinkType, snaplen uint32) error {
	if w.writer == nil {
		return errors.New("pcapng writer is not open")
	}
	if uint64(len(data)) > math.MaxUint32 {
		return fmt.Errorf("packet capture length %d exceeds pcapng limit", len(data))
	}
	ci.CaptureLength = len(data)
	if ci.Length < ci.CaptureLength {
		ci.Length = ci.CaptureLength
	}
	if uint64(ci.Length) > math.MaxUint32 { //nolint:gosec // ci.Length was raised to len(data) above, so it is non-negative
		return fmt.Errorf("packet wire length %d exceeds pcapng limit", ci.Length)
	}
	if ci.Timestamp.IsZero() {
		// Enhanced Packet Blocks require a timestamp; use a stable sentinel.
		ci.Timestamp = time.Unix(0, 0).UTC()
	}
	if snaplen == 0 {
		snaplen = uint32(ci.CaptureLength) //nolint:gosec // bounded above
	}
	key := ngInterfaceKey{linkType: linkType, snaplen: snaplen}
	interfaceIndex, ok := w.interfaces[key]
	if !ok {
		intf := pcapgo.DefaultNgInterface
		intf.LinkType = linkType
		intf.SnapLength = snaplen
		var err error
		interfaceIndex, err = w.writer.AddInterface(intf)
		if err != nil {
			return fmt.Errorf("add pcapng interface for %s: %w", linkType, err)
		}
		w.interfaces[key] = interfaceIndex
	}
	ci.InterfaceIndex = interfaceIndex
	ci.AncillaryData = nil
	if err := w.writer.WritePacket(ci, data); err != nil {
		return fmt.Errorf("write packet to pcapng %q: %w", w.path, err)
	}
	return nil
}

// Close flushes the pcapng stream and closes its file. It is idempotent.
func (w *NgWriter) Close() error {
	if w == nil {
		return nil
	}
	var errs []error
	if w.writer != nil {
		if err := w.writer.Flush(); err != nil {
			errs = append(errs, fmt.Errorf("flush pcapng %q: %w", w.path, err))
		}
		w.writer = nil
	}
	if err := w.closeFile(); err != nil {
		errs = append(errs, err)
	}
	w.interfaces = nil
	return errors.Join(errs...)
}

// Flush makes all buffered pcapng blocks visible without closing the stream.
func (w *NgWriter) Flush() error {
	if w == nil || w.writer == nil {
		return errors.New("pcapng writer is not open")
	}
	if err := w.writer.Flush(); err != nil {
		return fmt.Errorf("flush pcapng %q: %w", w.path, err)
	}
	return nil
}

func (w *NgWriter) closeFile() error {
	if w.file == nil {
		return nil
	}
	file := w.file
	w.file = nil
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pcapng %q: %w", w.path, err)
	}
	return nil
}
