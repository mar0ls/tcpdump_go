// Package capture handles live network packet capture via libpcap:
// opening interfaces, listing available interfaces, and signal handling.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"tcpdump_go/display"
	"tcpdump_go/offline"
	"tcpdump_go/rotation"
	"tcpdump_go/stats"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const (
	defaultBufKB     uint32 = 2048
	defaultSnaplen   uint32 = 262144
	captureReadWait         = 250 * time.Millisecond
	outputFlushEvery        = 5 * time.Millisecond
	minCaptureQueue         = 2048
	maxCaptureQueue         = 65536
)

// ErrNotPrivileged reports that -Z was asked for by a process that is not
// root. tcpdump treats that as a no-op because there is nothing to drop, so
// callers warn and carry on rather than failing.
var ErrNotPrivileged = errors.New("not running as root, so there are no privileges to drop")

// Config holds all parameters for a live packet capture session.
type Config struct {
	Iface          string
	Filter         string
	OutPcap        string
	PcapNG         bool
	Snaplen        uint32
	BufSize        uint32
	Promisc        bool
	RotateSize     uint64
	RotateTime     uint64
	MaxFiles       uint64
	ViewMode       display.ViewMode
	TSMode         display.TSMode
	Verbosity      int
	DisableDNS     bool
	ShowStats      bool
	Quiet          bool
	Count          uint64
	DisableOffload bool
	StatusWriter   io.Writer

	// DropUser is tcpdump's -Z: switch to this account once the handle is open.
	DropUser string
	// NoImmediateMode waits for the kernel buffer to fill instead of delivering
	// each packet as it arrives. Inverted so the zero value keeps the old
	// (immediate) behaviour.
	NoImmediateMode bool

	// FlushEveryPacket requests packet-buffered output, matching tcpdump's -l
	// and -U behaviour for the human-readable live stream.
	FlushEveryPacket bool
	// FlushPcapEveryPacket implements tcpdump's -U for raw capture output.
	FlushPcapEveryPacket bool
}

// RunCapture starts a live packet capture and processes packets until
// Ctrl+C / SIGTERM, or until cfg.Count packets have been seen (0 = unlimited).
// All resources are closed and already captured packets are processed before
// the function returns.
func RunCapture(cfg Config) (retErr error) {
	status := cfg.StatusWriter
	if status == nil {
		status = os.Stderr
	}
	if cfg.Iface == "" {
		if err := PrintInterfaces(cfg.Verbosity); err != nil {
			return err
		}
		return errors.New("specify an interface with -i <name>")
	}
	if cfg.Snaplen == 0 {
		// tcpdump treats -s 0 as its maximum/default snapshot length.
		cfg.Snaplen = defaultSnaplen
	}
	if _, _, err := libpcapParameters(cfg.Snaplen, cfg.BufSize); err != nil {
		return err
	}
	// Restoring offloads needs the privileges -Z gives away.
	if cfg.DropUser != "" && cfg.DisableOffload {
		return errors.New("-Z cannot be combined with --disable-offload: restoring NIC offloads requires the privileges being dropped")
	}

	handle, err := OpenHandle(cfg.Iface, cfg.Snaplen, cfg.BufSize, cfg.Promisc, !cfg.NoImmediateMode)
	if err != nil {
		return err
	}
	defer handle.Close()

	if cfg.Filter != "" {
		if err := handle.SetBPFFilter(cfg.Filter); err != nil {
			return fmt.Errorf("set BPF filter %q: %w", cfg.Filter, err)
		}
		if _, err := fmt.Fprintf(status, "BPF filter: %s\n", cfg.Filter); err != nil {
			return fmt.Errorf("write capture status: %w", err)
		}
	}

	// Drop before opening output files (they get the target user) and before
	// decoding anything off the wire.
	if err := DropPrivileges(cfg.DropUser); err != nil {
		if !errors.Is(err, ErrNotPrivileged) {
			return err
		}
		if _, err := fmt.Fprintf(status, "-Z ignored: %v\n", ErrNotPrivileged); err != nil {
			return fmt.Errorf("write capture status: %w", err)
		}
	}

	var (
		writeRaw   func(gopacket.CaptureInfo, []byte) error
		flushRaw   func() error
		closeRaw   func() error
		outputName = cfg.OutPcap
	)
	if cfg.OutPcap != "" {
		out, err := openRawOutput(cfg, handle.LinkType())
		if err != nil {
			return err
		}
		writeRaw, flushRaw, closeRaw, outputName = out.write, out.flush, out.close, out.name
		defer func() {
			retErr = errors.Join(retErr, closeRaw())
		}()
	}

	if _, err := fmt.Fprintf(status, "Capturing on %s (snaplen=%d, promisc=%v)\n", cfg.Iface, cfg.Snaplen, cfg.Promisc); err != nil {
		return fmt.Errorf("write capture status: %w", err)
	}
	if _, err := fmt.Fprintln(status, "Press Ctrl+C to stop."); err != nil {
		return fmt.Errorf("write capture status: %w", err)
	}
	if cfg.OutPcap != "" {
		if _, err := fmt.Fprintf(status, "Writing to: %s\n", outputName); err != nil {
			return fmt.Errorf("write capture status: %w", err)
		}
	}

	// Changing NIC state is deliberately the last setup action: the handle and
	// BPF are known to be valid, the output is open, and every later return path
	// runs the restoration function.
	if cfg.DisableOffload {
		restore, err := DisableOffloading(cfg.Iface)
		if err != nil {
			return fmt.Errorf("disable offloading on %s: %w", cfg.Iface, err)
		}
		defer func() {
			if restore != nil {
				retErr = errors.Join(retErr, restore())
			}
		}()
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), ShutdownSignals...)
	defer stopSignals()

	st := stats.NewStats()
	var runErr error
	if rawWriteOnly(cfg) {
		runErr = runRawWritePipeline(signalCtx, handle, cfg.Count, writeRaw, flushRaw, cfg.FlushPcapEveryPacket, &st.Total)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = true

		var prevTS time.Time
		process := func(cp capturedPacket) error {
			packet := cp.packet
			ci := packet.Metadata().CaptureInfo
			st.Update(packet)
			if !cfg.Quiet {
				if err := display.PrintPacket(cp.num, packet, ci.Timestamp, prevTS, cfg.ViewMode, cfg.TSMode, cfg.Verbosity, cfg.DisableDNS); err != nil {
					return fmt.Errorf("print packet %d: %w", cp.num, err)
				}
			}
			prevTS = ci.Timestamp
			if cfg.OutPcap != "" {
				if err := writeRaw(ci, packet.Data()); err != nil {
					return err
				}
				if cfg.FlushPcapEveryPacket {
					if err := flushRaw(); err != nil {
						return err
					}
				}
			}
			return nil
		}

		var flush func() error
		if !cfg.Quiet {
			flush = display.FlushOut
		}
		runErr = runPacketPipeline(signalCtx, packetSource, cfg.Count, captureQueueDepth(cfg.BufSize), defaultQueueBytes, process, flush, cfg.FlushEveryPacket)
	}

	// -W with -G ends the capture on purpose once the file count is reached.
	if errors.Is(runErr, rotation.ErrFileLimitReached) {
		runErr = nil
	}

	pcapStats, statsErr := handle.Stats()
	if statsErr != nil {
		statsErr = fmt.Errorf("read capture statistics: %w", statsErr)
	} else if pcapStats.PacketsDropped > 0 {
		st.Dropped.Store(uint64(pcapStats.PacketsDropped))
	}
	summaryErr := printCaptureSummary(status, st.Total, pcapStats)
	var statsPrintErr error
	if cfg.ShowStats {
		if err := st.Print(); err != nil {
			statsPrintErr = fmt.Errorf("print capture statistics: %w", err)
		}
	}
	flushErr := display.FlushOut()
	if flushErr != nil {
		flushErr = fmt.Errorf("flush output: %w", flushErr)
	}
	return errors.Join(runErr, statsErr, summaryErr, statsPrintErr, flushErr)
}

// rawOutput is the set of writer callbacks -w installs.
type rawOutput struct {
	write func(gopacket.CaptureInfo, []byte) error
	flush func() error
	close func() error
	name  string
}

// openRawOutput builds the -w writer for linkType. It is separate from
// RunCapture so that every rotation setting it has to forward can be checked
// without opening an interface; -W reaching the writer was missed here once.
func openRawOutput(cfg Config, linkType layers.LinkType) (rawOutput, error) {
	if cfg.PcapNG {
		if cfg.RotateSize > 0 || cfg.RotateTime > 0 {
			return rawOutput{}, errors.New("pcapng rotation is not supported")
		}
		writer := offline.NewNgWriter(cfg.OutPcap)
		if err := writer.Open(linkType, cfg.Snaplen); err != nil {
			return rawOutput{}, err
		}
		return rawOutput{
			write: func(ci gopacket.CaptureInfo, data []byte) error {
				return writer.WritePacket(ci, data, linkType, cfg.Snaplen)
			},
			flush: writer.Flush,
			close: writer.Close,
			name:  cfg.OutPcap,
		}, nil
	}
	writer := rotation.NewPcapWriter(cfg.OutPcap, cfg.Snaplen, linkType, cfg.RotateSize, cfg.RotateTime)
	writer.SetMaxFiles(cfg.MaxFiles)
	if err := writer.Open(); err != nil {
		return rawOutput{}, err
	}
	return rawOutput{
		write: writer.WritePacket,
		flush: writer.Flush,
		close: writer.Close,
		name:  writer.Filename(),
	}, nil
}

// printCaptureSummary writes tcpdump's closing counters to the status stream,
// never to stdout. Kernel counters are skipped when libpcap could not supply
// them rather than printed as zero.
func printCaptureSummary(status io.Writer, captured uint64, pcapStats *pcap.Stats) error {
	if _, err := fmt.Fprintf(status, "%d packets captured\n", captured); err != nil {
		return fmt.Errorf("write capture summary: %w", err)
	}
	if pcapStats == nil {
		return nil
	}
	if _, err := fmt.Fprintf(status, "%d packets received by filter\n%d packets dropped by kernel\n",
		max(0, pcapStats.PacketsReceived), max(0, pcapStats.PacketsDropped)); err != nil {
		return fmt.Errorf("write capture summary: %w", err)
	}
	return nil
}

// PrintInterfaces lists all network interfaces available to libpcap.
func PrintInterfaces(verbosity int) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	// tcpdump -D numbers the devices from 1 and -i accepts those numbers.
	for index, d := range devices {
		line := fmt.Sprintf("%d.%s [%s]", index+1, display.Colorize(d.Name, display.ColorGreen), interfaceFlagNames(d.Flags))
		if verbosity > 0 && len(d.Addresses) > 0 {
			addrs := make([]string, 0, len(d.Addresses))
			for _, a := range d.Addresses {
				addrs = append(addrs, a.IP.String())
			}
			line += " " + strings.Join(addrs, ", ")
		}
		if err := display.Outln(line); err != nil {
			return fmt.Errorf("write interface list: %w", err)
		}
	}
	if err := display.FlushOut(); err != nil {
		return fmt.Errorf("flush interface list: %w", err)
	}
	return nil
}

// OpenHandle opens a pcap handle on iface with the given snaplen, buffer size
// (KB), promiscuous-mode, and immediate-delivery settings. A finite read
// timeout makes signal-driven shutdown safe without closing a handle
// concurrently with a blocked read.
func OpenHandle(iface string, snaplen, bufSize uint32, promisc, immediate bool) (*pcap.Handle, error) {
	snaplenInt, bufferBytes, err := libpcapParameters(snaplen, bufSize)
	if err != nil {
		return nil, err
	}
	if iface == "" {
		return nil, errors.New("interface name is empty")
	}

	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("create handle for %s: %w", iface, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snaplenInt); err != nil {
		return nil, fmt.Errorf("set snaplen %d: %w", snaplenInt, err)
	}
	if err := inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %w", err)
	}
	if err := inactive.SetTimeout(captureReadWait); err != nil {
		return nil, fmt.Errorf("set capture timeout: %w", err)
	}
	if err := inactive.SetBufferSize(bufferBytes); err != nil {
		return nil, fmt.Errorf("set capture buffer to %d bytes: %w", bufferBytes, err)
	}
	if err := inactive.SetImmediateMode(immediate); err != nil {
		return nil, fmt.Errorf("set immediate capture mode to %v: %w", immediate, err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate interface %s: %w", iface, err)
	}
	return handle, nil
}

// libpcapParameters converts unsigned CLI/config values only after checking
// the signed C int ranges used by libpcap. This is intentionally kept pure so
// boundary behaviour is testable without opening an interface.
func libpcapParameters(snaplen, bufSize uint32) (int, int, error) {
	if snaplen == 0 {
		snaplen = defaultSnaplen
	}
	if uint64(snaplen) > uint64(math.MaxInt32) {
		return 0, 0, fmt.Errorf("snaplen %d exceeds libpcap limit %d", snaplen, int64(math.MaxInt32))
	}
	if bufSize == 0 {
		bufSize = defaultBufKB
	}
	bufferBytes := uint64(bufSize) * 1024
	if bufferBytes > uint64(math.MaxInt32) {
		return 0, 0, fmt.Errorf("capture buffer %d KB exceeds libpcap limit of %d bytes", bufSize, int64(math.MaxInt32))
	}
	return int(snaplen), int(bufferBytes), nil
}

// defaultQueueBytes caps the packet data held between reader and renderer.
const defaultQueueBytes int64 = 64 << 20

func captureQueueDepth(bufSize uint32) int {
	if bufSize == 0 {
		bufSize = defaultBufKB
	}
	depth := int(uint64(bufSize) * 1024 / 1500)
	return min(max(depth, minCaptureQueue), maxCaptureQueue)
}

type packetReader interface {
	NextPacket() (gopacket.Packet, error)
}

type capturedPacket struct {
	packet gopacket.Packet
	num    uint64
	size   int
}

// flightControl bounds the packet bytes waiting between the reader and the
// renderer. A queue measured only in packets cannot tell a 64-byte ACK from a
// jumbo frame, so with a large -B it can hold hundreds of megabytes.
//
// One producer and one consumer: only the producer adds, only the consumer
// subtracts, so the check-then-add below cannot race.
type flightControl struct {
	inFlight atomic.Int64
	limit    int64
	drained  chan struct{}
}

func newFlightControl(limit int64) *flightControl {
	return &flightControl{limit: limit, drained: make(chan struct{}, 1)}
}

// admit blocks until size bytes fit, and reports false if ctx ends first. A
// packet larger than the whole budget is admitted alone rather than deadlocking.
func (f *flightControl) admit(ctx context.Context, size int) bool {
	for f.inFlight.Load() > 0 && f.inFlight.Load()+int64(size) > f.limit {
		select {
		case <-f.drained:
		case <-ctx.Done():
			return false
		}
	}
	f.inFlight.Add(int64(size))
	return true
}

// release returns a processed packet's bytes to the budget.
func (f *flightControl) release(size int) {
	f.inFlight.Add(-int64(size))
	select {
	case f.drained <- struct{}{}:
	default: // the producer is not waiting; it re-checks the budget anyway
	}
}

type rawPacketReader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// rawWriteOnly reports whether the session writes packets to a file and
// nothing else looks inside them. Statistics decode every network and
// transport header, so they are only free to skip when -stats is off.
func rawWriteOnly(cfg Config) bool {
	return cfg.OutPcap != "" && cfg.Quiet && !cfg.ShowStats
}

// runRawWritePipeline is the -w path for a session that never decodes a
// packet: libpcap's own buffer goes straight to the writer, so no
// gopacket.Packet is built and nothing is copied per packet.
//
// Single-threaded on purpose. The zero-copy buffer is only valid until the
// next read, so handing it to another goroutine would mean copying it back,
// and a buffered file writer is not the slow side of this loop; measured on
// 2M packets, the copy-and-queue variant costs about as much as the decoding
// path it replaces.
func runRawWritePipeline(
	stopCtx context.Context,
	source rawPacketReader,
	count uint64,
	write func(gopacket.CaptureInfo, []byte) error,
	flush func() error,
	flushEveryPacket bool,
	captured *uint64,
) error {
	for count == 0 || *captured < count {
		if stopCtx.Err() != nil {
			return nil
		}

		data, ci, err := source.ZeroCopyReadPacketData()
		if err != nil {
			if stopCtx.Err() != nil {
				return nil
			}
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("live capture ended unexpectedly: %w", err)
			}
			return fmt.Errorf("read packet: %w", err)
		}

		*captured++
		if err := write(ci, data); err != nil {
			return err
		}
		if flushEveryPacket {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

// runPacketPipeline decouples libpcap reads from potentially slower packet
// rendering. On graceful cancellation, packets that have already been read
// are drained; on a processing failure, the producer is aborted promptly.
func runPacketPipeline(
	stopCtx context.Context,
	source packetReader,
	count uint64,
	queueDepth int,
	queueBytes int64,
	process func(capturedPacket) error,
	flush func() error,
	flushEveryPacket bool,
) error {
	if queueDepth < 1 {
		queueDepth = 1
	}
	if queueBytes < 1 {
		queueBytes = defaultQueueBytes
	}
	packets := make(chan capturedPacket, queueDepth)
	readResult := make(chan error, 1)
	abortCtx, abort := context.WithCancel(context.Background())
	defer abort()
	budget := newFlightControl(queueBytes)

	go func() {
		readResult <- producePackets(stopCtx, abortCtx, source, count, packets, budget)
		close(packets)
	}()

	var (
		ticker     *time.Ticker
		tick       <-chan time.Time
		dirty      bool
		processErr error
	)
	if flush != nil && !flushEveryPacket {
		ticker = time.NewTicker(outputFlushEvery)
		tick = ticker.C
		defer ticker.Stop()
	}

	for packets != nil {
		select {
		case cp, ok := <-packets:
			if !ok {
				packets = nil
				continue
			}
			budget.release(cp.size)
			if processErr != nil {
				continue
			}
			if err := process(cp); err != nil {
				processErr = err
				abort()
				continue
			}
			if flush == nil {
				continue
			}
			if flushEveryPacket {
				if err := flush(); err != nil {
					processErr = fmt.Errorf("flush packet output: %w", err)
					abort()
				}
			} else {
				dirty = true
			}
		case <-tick:
			if dirty && processErr == nil {
				if err := flush(); err != nil {
					processErr = fmt.Errorf("flush packet output: %w", err)
					abort()
				}
				dirty = false
			}
		}
	}

	readErr := <-readResult
	if dirty && processErr == nil {
		if err := flush(); err != nil {
			processErr = fmt.Errorf("flush packet output: %w", err)
		}
	}
	return errors.Join(processErr, readErr)
}

func producePackets(
	stopCtx context.Context,
	abortCtx context.Context,
	source packetReader,
	count uint64,
	packets chan<- capturedPacket,
	budget *flightControl,
) error {
	var packetNum uint64
	for count == 0 || packetNum < count {
		if stopCtx.Err() != nil || abortCtx.Err() != nil {
			return nil
		}

		packet, err := source.NextPacket()
		if err != nil {
			if stopCtx.Err() != nil || abortCtx.Err() != nil {
				return nil
			}
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("live capture ended unexpectedly: %w", err)
			}
			return fmt.Errorf("read packet: %w", err)
		}

		packetNum++
		cp := capturedPacket{packet: packet, num: packetNum, size: len(packet.Data())}
		// Wait for room before queueing, so a slow renderer bounds memory
		// instead of letting the queue grow to queueDepth jumbo frames.
		if !budget.admit(abortCtx, cp.size) {
			return nil
		}
		select {
		case packets <- cp:
		case <-abortCtx.Done():
			budget.release(cp.size)
			return nil
		}
	}
	return nil
}
