// Package rawout writes captured packets back out as classic pcap or pcapng.
// It defers creating the file until the first packet, because the link type
// and snap length are only known once a record has been read.
package rawout

import (
	"errors"
	"fmt"
	"tcpdump_go/offline"
	"tcpdump_go/rotation"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Config describes the requested output; a zero rotation value disables it.
type Config struct {
	Path       string
	PcapNG     bool
	RotateSize uint64
	RotateTime uint64
	MaxFiles   uint64
}

// Output is a lazily opened raw packet sink.
type Output struct {
	path       string
	pcapng     bool
	rotateSize uint64
	rotateTime uint64
	maxFiles   uint64
	classic    *rotation.PcapWriter
	ng         *offline.NgWriter
	linkType   layers.LinkType
	opened     bool
}

// New returns an Output that stays closed until Open is called.
func New(config Config) *Output {
	return &Output{
		path:       config.Path,
		pcapng:     config.PcapNG,
		rotateSize: config.RotateSize,
		rotateTime: config.RotateTime,
		maxFiles:   config.MaxFiles,
	}
}

// IsOpen reports whether the sink is ready (or not needed at all).
func (output *Output) IsOpen() bool {
	return output == nil || output.path == "" || output.opened
}

// Open creates the file for the given link type and snap length.
func (output *Output) Open(linkType layers.LinkType, snaplen uint32) error {
	if output == nil || output.path == "" {
		return nil
	}
	if output.opened {
		return errors.New("raw packet output is already open")
	}
	output.linkType = linkType
	if output.pcapng {
		output.ng = offline.NewNgWriter(output.path)
		if err := output.ng.Open(linkType, snaplen); err != nil {
			return err
		}
	} else {
		output.classic = rotation.NewPcapWriter(output.path, snaplen, linkType, output.rotateSize, output.rotateTime)
		output.classic.SetMaxFiles(output.maxFiles)
		if err := output.classic.Open(); err != nil {
			return err
		}
	}
	output.opened = true
	return nil
}

// WritePacket appends one record.
func (output *Output) WritePacket(captureInfo gopacket.CaptureInfo, data []byte, linkType layers.LinkType, snaplen uint32) error {
	if output == nil || output.path == "" {
		return nil
	}
	if !output.opened {
		if err := output.Open(linkType, snaplen); err != nil {
			return err
		}
	}
	if output.pcapng {
		return output.ng.WritePacket(captureInfo, data, linkType, snaplen)
	}
	if linkType != output.linkType {
		return fmt.Errorf("classic pcap cannot contain both %s and %s; use a .pcapng output", output.linkType, linkType)
	}
	return output.classic.WritePacket(captureInfo, data)
}

// Flush makes buffered records visible without closing the file.
func (output *Output) Flush() error {
	if output == nil || output.path == "" || !output.opened {
		return nil
	}
	if output.pcapng {
		return output.ng.Flush()
	}
	return output.classic.Flush()
}

// Close finishes the file. It is idempotent.
func (output *Output) Close() error {
	if output == nil || !output.opened {
		return nil
	}
	output.opened = false
	if output.pcapng {
		return output.ng.Close()
	}
	return output.classic.Close()
}
