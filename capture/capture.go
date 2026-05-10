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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

const defaultBufKB uint32 = 2048

// Config holds all parameters for a live packet capture session.
type Config struct {
	Iface          string
	Filter         string
	OutPcap        string
	Snaplen        uint32
	BufSize        uint32
	Promisc        bool
	RotateSize     uint64
	RotateTime     uint64
	ViewMode       display.ViewMode
	TSMode         display.TSMode
	Verbose        bool
	DisableDNS     bool
	ShowStats      bool
	Quiet          bool
	Count          uint64
	DisableOffload bool
}

// RunCapture starts a live packet capture and processes packets until
// Ctrl+C / SIGTERM, or until cfg.Count packets have been seen (0 = unlimited).
func RunCapture(cfg Config) {
	if cfg.Iface == "" {
		PrintInterfaces()
		log.Fatal("specify an interface with -i <name>")
	}
	if cfg.DisableOffload {
		DisableOffloading(cfg.Iface)
	}
	handle := OpenHandle(cfg.Iface, cfg.Snaplen, cfg.BufSize, cfg.Promisc)
	if cfg.Filter != "" {
		if err := handle.SetBPFFilter(cfg.Filter); err != nil {
			handle.Close()
			log.Fatalf("BPF filter error: %v", err)
		}
		display.Outf("%s %s\n", display.Colorize("BPF filter:", display.ColorYellow), cfg.Filter)
	}
	defer handle.Close()
	display.Outf("%s %s (snaplen=%d, promisc=%v)\n",
		display.Colorize("Capturing on", display.ColorCyan), display.Colorize(cfg.Iface, display.ColorGreen), cfg.Snaplen, cfg.Promisc)
	display.Outln(display.Colorize("Press Ctrl+C to stop.", display.ColorGray))
	display.FlushOut()
	pw := rotation.NewPcapWriter(cfg.OutPcap, cfg.Snaplen, handle.LinkType(), cfg.RotateSize, cfg.RotateTime)
	if cfg.OutPcap != "" {
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
	effectiveBuf := cfg.BufSize
	if effectiveBuf == 0 {
		effectiveBuf = defaultBufKB
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
			if cfg.Count > 0 && pktNum >= cfg.Count {
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
				if !cfg.Quiet {
					display.PrintPacket(cp.num, cp.packet, ts, prevTS, cfg.ViewMode, cfg.TSMode, cfg.Verbose, cfg.DisableDNS)
				}
				prevTS = ts
				st.Update(cp.packet)
				if cfg.OutPcap != "" {
					pw.WritePacket(ts, cp.packet.Data())
				}
			}
			if !cfg.Quiet && len(batch) > 0 {
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
	if cfg.ShowStats || st.Dropped.Load() > 0 {
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

// OpenHandle opens a pcap handle on iface with the given snaplen, buffer size (KB), and promisc flag.
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
