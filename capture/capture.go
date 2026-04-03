// Package capture handles live network packet capture via libpcap:
// opening interfaces, listing available interfaces, and signal handling.
package capture

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"tcpdump_go/display"
	"tcpdump_go/rotation"
	"tcpdump_go/stats"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// RunCapture starts a live packet capture on iface and processes packets until
// Ctrl+C (or SIGTERM), or until count packets have been seen (0 = unlimited).
// Captured packets are decoded, optionally written to outPcap, and displayed
// according to viewMode/tsMode. Statistics are printed if showStats is true.
func RunCapture(
	iface, filter, outPcap string,
	snaplen, bufSize uint32,
	promisc bool,
	rotateSize, rotateTime uint64,
	viewMode, tsMode string,
	verbose, disableDNS, showStats, quiet bool,
	count uint64,
	disableOffload bool,
) {
	if iface == "" {
		PrintInterfaces()
		log.Fatal("specify an interface with -i <name>")
	}
	if disableOffload {
		DisableOffloading(iface)
	}
	handle := OpenHandle(iface, snaplen, bufSize, promisc)
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			log.Fatalf("BPF filter error: %v", err)
		}
		display.Outf("%s %s\n", display.Colorize("BPF filter:", display.ColorYellow), filter)
	}
	defer handle.Close()
	display.Outf("%s %s (snaplen=%d, promisc=%v)\n",
		display.Colorize("Capturing on", display.ColorCyan), display.Colorize(iface, display.ColorGreen), snaplen, promisc)
	display.Outln(display.Colorize("Press Ctrl+C to stop.", display.ColorGray))
	display.FlushOut()
	pw := rotation.NewPcapWriter(outPcap, snaplen, handle.LinkType(), rotateSize, rotateTime)
	if outPcap != "" {
		pw.Open()
		display.Outf("%s %s\n", display.Colorize("Writing to:", display.ColorCyan), pw.Filename())
		display.FlushOut()
		defer pw.Close()
	}
	st := stats.NewStats()
	setupSignalHandler(handle, st)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true
	const defaultBufKBQueue uint32 = 2048
	effectiveBuf := bufSize
	if effectiveBuf == 0 {
		effectiveBuf = defaultBufKBQueue
	}
	captureChDepth := min(max(int(uint64(effectiveBuf)*1024/1500), 2048), 65536)
	type capturedPkt struct {
		packet gopacket.Packet
		num    uint64
	}
	captureCh := make(chan capturedPkt, captureChDepth)
	var pktNum uint64
	go func() {
		defer close(captureCh)
		for packet := range packetSource.Packets() {
			pktNum++
			captureCh <- capturedPkt{packet, pktNum}
			if count > 0 && pktNum >= count {
				return
			}
		}
	}()
	const batchCap = 64
	done := make(chan struct{})
	go func() {
		defer close(done)
		var prevTS time.Time
		batch := make([]capturedPkt, 0, batchCap)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		flush := func() {
			for _, cp := range batch {
				ts := cp.packet.Metadata().Timestamp
				if !quiet {
					display.PrintPacket(cp.num, cp.packet, ts, prevTS, viewMode, tsMode, verbose, disableDNS)
				}
				prevTS = ts
				st.Update(cp.packet)
				if outPcap != "" {
					pw.WritePacket(ts, cp.packet.Data())
				}
			}
			if !quiet && len(batch) > 0 {
				display.FlushOut()
			}
			batch = batch[:0]
		}
		for {
			select {
			case cp, ok := <-captureCh:
				if !ok {
					flush()
					return
				}
				batch = append(batch, cp)
				if len(batch) >= batchCap {
					flush()
				}
			case <-ticker.C:
				if len(batch) > 0 {
					flush()
				}
			}
		}
	}()
	<-done
	if showStats || st.Dropped.Load() > 0 {
		st.Print()
		display.FlushOut()
	}
}

// PrintInterfaces lists all network interfaces available to libpcap and exits.
func PrintInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("list interfaces: %v", err)
	}
	display.Outln(display.Colorize("Available interfaces:", display.ColorCyan))
	for _, d := range devices {
		addrs := make([]string, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			addrs = append(addrs, a.IP.String())
		}
		display.Outf("  %s\t%s\n", display.Colorize(d.Name, display.ColorGreen), strings.Join(addrs, ", "))
	}
	display.FlushOut()
}

// OpenHandle opens an activated pcap handle for iface with the specified
// snaplen and buffer size (KB). It enables promiscuous mode if promisc is true
// and sets immediate mode for low-latency delivery.
func OpenHandle(iface string, snaplen, bufSize uint32, promisc bool) *pcap.Handle {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		log.Fatalf("create handle for %s: %v", iface, err)
	}
	if err := inactive.SetSnapLen(int(snaplen)); err != nil {
		inactive.CleanUp()
		log.Fatalf("set snaplen: %v", err)
	}
	if err := inactive.SetPromisc(promisc); err != nil {
		inactive.CleanUp()
		log.Fatalf("set promisc: %v", err)
	}
	if err := inactive.SetTimeout(pcap.BlockForever); err != nil {
		inactive.CleanUp()
		log.Fatalf("set timeout: %v", err)
	}
	const defaultBufKB uint32 = 2048
	if bufSize == 0 {
		bufSize = defaultBufKB
	}
	if err := inactive.SetBufferSize(int(uint64(bufSize) * 1024)); err != nil {
		log.Printf("warning: SetBufferSize %d KB: %v", bufSize, err)
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		log.Printf("warning: SetImmediateMode unavailable: %v", err)
	}
	handle, err := inactive.Activate()
	if err != nil {
		inactive.CleanUp()
		log.Fatalf("activate interface %s: %v", iface, err)
	}
	return handle
}

func setupSignalHandler(handle *pcap.Handle, st *stats.Stats) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, ShutdownSignals...)
	go func() {
		<-sigCh
		if ps, err := handle.Stats(); err == nil && ps.PacketsDropped > 0 {
			st.Dropped.Store(uint64(ps.PacketsDropped))
		}
		handle.Close()
	}()
}
