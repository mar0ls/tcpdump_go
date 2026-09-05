package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"tcpdump_go/capture"
	"tcpdump_go/display"
	"tcpdump_go/internal/rawout"
	"tcpdump_go/offline"
	"tcpdump_go/rotation"
	"tcpdump_go/stats"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type flowKey struct {
	Src, Dst, Sport, Dport, Proto string
}

type filterKey struct {
	linkType layers.LinkType
	snaplen  uint32
}

func runReadPcap(options cliOptions, viewMode display.ViewMode, tsMode display.TSMode, printPackets bool, stdout, stderr io.Writer) (retErr error) {
	reader, err := offline.Open(options.readPcap)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, reader.Close()) }()

	// Decoding an untrusted capture is exactly the work that should not run as
	// root. The input is already open, so privileges are dropped before any
	// record is parsed and before the output files are created.
	if err := capture.DropPrivileges(options.dropUser); err != nil {
		if !errors.Is(err, capture.ErrNotPrivileged) {
			return err
		}
		if _, err := fmt.Fprintf(stderr, "-Z ignored: %v\n", capture.ErrNotPrivileged); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
	}

	rawOutput := rawout.New(rawout.Config{
		Path:       options.outPcap,
		PcapNG:     options.pcapngOutput,
		RotateSize: options.rotateSize,
		RotateTime: options.rotateTime,
		MaxFiles:   options.maxFiles,
	})
	defer func() { retErr = errors.Join(retErr, rawOutput.Close()) }()

	filters := make(map[filterKey]*pcap.BPF)
	compileFilter := func(linkType layers.LinkType, snaplen uint32) (*pcap.BPF, error) {
		if options.filter == "" {
			return nil, nil
		}
		if snaplen == 0 {
			snaplen = uint32(defaultSnaplen)
		}
		if snaplen > math.MaxInt32 {
			return nil, fmt.Errorf("capture snaplen %d exceeds BPF compiler limit", snaplen)
		}
		key := filterKey{linkType: linkType, snaplen: snaplen}
		if compiled, ok := filters[key]; ok {
			return compiled, nil
		}
		compiled, err := pcap.NewBPF(linkType, int(snaplen), options.filter)
		if err != nil {
			return nil, fmt.Errorf("compile BPF %q for %s: %w", options.filter, linkType, err)
		}
		filters[key] = compiled
		return compiled, nil
	}

	// Classic pcap exposes its only link type in the file header, so validate
	// BPF and create a header even when the file has no packets or none match.
	if !reader.IsNg() {
		if _, err := compileFilter(reader.LinkType(), reader.Snaplen()); err != nil {
			return err
		}
		if options.outPcap != "" {
			if err := rawOutput.Open(reader.LinkType(), normalizedSnaplen(reader.Snaplen(), 0)); err != nil {
				return err
			}
		}
	}

	statistics := stats.NewStats()
	flows := make(map[flowKey]uint64)
	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	decodePackets := printPackets || options.showStats || options.csvOut != ""
	var (
		recordNumber uint64
		packetNumber uint64
		previousTS   time.Time
		firstLink    layers.LinkType
		firstSnaplen uint32
		sawRecord    bool
	)

	for {
		data, captureInfo, linkType, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read capture record %d from %q: %w", recordNumber+1, options.readPcap, err)
		}
		recordNumber++
		snaplen := normalizedSnaplen(reader.PacketSnaplen(captureInfo), len(data))
		if !sawRecord {
			firstLink, firstSnaplen, sawRecord = linkType, snaplen, true
		}
		compiled, err := compileFilter(linkType, snaplen)
		if err != nil {
			return err
		}
		if compiled != nil && !compiled.Matches(captureInfo, data) {
			continue
		}
		if options.outPcap != "" && !rawOutput.IsOpen() {
			if err := rawOutput.Open(linkType, snaplen); err != nil {
				return err
			}
		}

		packetNumber++
		// Building and decoding a packet is the most expensive work here, so
		// -r with -w and nothing else skips it entirely.
		if decodePackets {
			packet := gopacket.NewPacket(data, linkType, decodeOptions)
			metadata := packet.Metadata()
			metadata.CaptureInfo = captureInfo
			metadata.Truncated = metadata.Truncated || captureInfo.CaptureLength < captureInfo.Length

			if printPackets {
				if err := display.PrintPacket(packetNumber, packet, captureInfo.Timestamp, previousTS, viewMode, tsMode, options.verbosity, options.disableDNS); err != nil {
					return fmt.Errorf("print packet %d: %w", packetNumber, err)
				}
			}
			previousTS = captureInfo.Timestamp
			statistics.Update(packet)
			if options.csvOut != "" {
				updateFlowMap(flows, packet)
			}
		}

		if options.outPcap != "" {
			if err := rawOutput.WritePacket(captureInfo, data, linkType, snaplen); err != nil {
				// -W with -G stops here by design, not because of a failure.
				if errors.Is(err, rotation.ErrFileLimitReached) {
					break
				}
				return fmt.Errorf("write packet %d: %w", packetNumber, err)
			}
			if options.packetBuffered {
				if err := rawOutput.Flush(); err != nil {
					return fmt.Errorf("flush packet %d: %w", packetNumber, err)
				}
			}
		}
		if options.count > 0 && packetNumber >= options.count {
			break
		}
	}
	if !sawRecord && reader.IsNg() && (options.filter != "" || options.outPcap != "") {
		firstInterface, err := reader.Interface(0)
		if err != nil {
			return fmt.Errorf("read first pcapng interface: %w", err)
		}
		firstLink = firstInterface.LinkType
		firstSnaplen = normalizedSnaplen(firstInterface.SnapLength, 0)
		if _, err := compileFilter(firstLink, firstSnaplen); err != nil {
			return err
		}
	}
	if options.outPcap != "" && !rawOutput.IsOpen() {
		if err := rawOutput.Open(firstLink, firstSnaplen); err != nil {
			return err
		}
	}

	if err := rawOutput.Close(); err != nil {
		return err
	}
	if options.countOnly {
		countOutput := stdout
		if options.outPcap == "-" {
			countOutput = stderr
		}
		if _, err := fmt.Fprintf(countOutput, "%d packets\n", packetNumber); err != nil {
			return fmt.Errorf("write packet count: %w", err)
		}
	}
	if options.showStats {
		if err := statistics.Print(); err != nil {
			return fmt.Errorf("print statistics: %w", err)
		}
	}
	if options.csvOut != "" {
		if err := writeCSV(options.csvOut, flows); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stderr, "CSV flows written: %s\n", options.csvOut); err != nil {
			return fmt.Errorf("write CSV status: %w", err)
		}
	}
	return nil
}

func normalizedSnaplen(source uint32, captured int) uint32 {
	if source == 0 {
		source = uint32(defaultSnaplen)
	}
	if captured > int(source) {
		source = uint32(captured) //nolint:gosec // packet lengths are bounded by pcap's uint32 fields
	}
	return source
}

func updateFlowMap(flows map[flowKey]uint64, packet gopacket.Packet) {
	network := packet.NetworkLayer()
	if network == nil {
		return
	}
	src, dst := network.NetworkFlow().Endpoints()
	proto, sport, dport := display.ExtractTransportInfo(packet)
	flows[flowKey{Src: src.String(), Dst: dst.String(), Sport: sport, Dport: dport, Proto: proto}]++
}

func writeCSV(outputPath string, flows map[flowKey]uint64) (retErr error) {
	directory := filepath.Dir(outputPath)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(outputPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary CSV beside %q: %w", outputPath, err)
	}
	temporaryPath := temporary.Name()
	renamed := false
	closed := false
	defer func() {
		if !renamed {
			if !closed {
				retErr = errors.Join(retErr, temporary.Close())
			}
			if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove temporary CSV %q: %w", temporaryPath, err))
			}
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set CSV permissions: %w", err)
	}

	writer := csv.NewWriter(temporary)
	if err := writer.Write([]string{"src_ip", "dst_ip", "src_port", "dst_port", "proto", "count"}); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	keys := make([]flowKey, 0, len(flows))
	for key := range flows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := strings.Join([]string{keys[i].Src, keys[i].Dst, keys[i].Sport, keys[i].Dport, keys[i].Proto}, "\x00")
		right := strings.Join([]string{keys[j].Src, keys[j].Dst, keys[j].Sport, keys[j].Dport, keys[j].Proto}, "\x00")
		return left < right
	})
	for _, key := range keys {
		record := []string{key.Src, key.Dst, key.Sport, key.Dport, key.Proto, fmt.Sprintf("%d", flows[key])}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write CSV record: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush CSV records: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync CSV %q: %w", temporaryPath, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close CSV %q: %w", temporaryPath, err)
	}
	closed = true
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("publish CSV %q: %w", outputPath, err)
	}
	renamed = true
	return nil
}
