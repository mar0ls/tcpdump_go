// tcpdump_go — network packet analyzer built on libpcap and gopacket.
// Supports live capture, pcap/pcapng file reading, BPF filters, file rotation,
// flow CSV export, and colorized output. Requires root or CAP_NET_RAW.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"tcpdump_go/capture"
	"tcpdump_go/display"
	"tcpdump_go/rotation"
	"tcpdump_go/stats"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// packetFileReader is the common interface for pcapgo.Reader and pcapgo.NgReader.
type packetFileReader interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
}

// pcapngMagic holds the first 4 bytes of a pcapng file (Section Header Block).
var pcapngMagic = [4]byte{0x0a, 0x0d, 0x0d, 0x0a}

// openPcapFile detects the file format by magic bytes and returns the appropriate reader.
// The caller is responsible for closing the returned file.
func openPcapFile(path string) (*os.File, packetFileReader) {
	f, err := os.Open(path) //#nosec G304 -- path comes from a CLI flag
	if err != nil {
		log.Fatalf("cannot open file: %v", err)
	}

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		if cerr := f.Close(); cerr != nil {
			log.Printf("close file: %v", cerr)
		}
		log.Fatalf("read file header: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		if cerr := f.Close(); cerr != nil {
			log.Printf("close file: %v", cerr)
		}
		log.Fatalf("seek file: %v", err)
	}

	if magic == pcapngMagic {
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			if cerr := f.Close(); cerr != nil {
				log.Printf("close file: %v", cerr)
			}
			log.Fatalf("open pcapng: %v", err)
		}
		display.Outf("%s pcapng\n", display.Colorize("Format:", display.ColorCyan))
		return f, r
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		if cerr := f.Close(); cerr != nil {
			log.Printf("close file: %v", cerr)
		}
		log.Fatalf("open pcap: %v", err)
	}
	return f, r
}

// boolFlags lists boolean flag names in descending length order for greedy matching.
var boolFlags = []string{"tttt", "ttt", "disable-offload", "promisc", "stats", "xx", "XX", "tt", "v", "x", "X", "n", "q", "t"}

// expandArgs splits POSIX-style combined flags: -nXX → -n -XX, -nv → -n -v.
func expandArgs(args []string) []string {
	out := make([]string, 0, len(args)+4)
	for _, arg := range args {
		if len(arg) < 3 || arg[0] != '-' || arg[1] == '-' {
			out = append(out, arg)
			continue
		}
		rest := arg[1:]
		expanded := make([]string, 0, 4)
		ok := true
		for len(rest) > 0 {
			matched := false
			for _, f := range boolFlags {
				if strings.HasPrefix(rest, f) {
					expanded = append(expanded, "-"+f)
					rest = rest[len(f):]
					matched = true
					break
				}
			}
			if !matched {
				ok = false
				break
			}
		}
		if ok && len(expanded) > 1 {
			out = append(out, expanded...)
		} else {
			out = append(out, arg)
		}
	}
	return out
}

func main() {
	os.Args = append(os.Args[:1], expandArgs(os.Args[1:])...)
	// Packet source
	iface := flag.String("i", "", "")
	readPcap := flag.String("r", "", "")
	filter := flag.String("f", "", "")
	count := flag.Uint64("c", 0, "")

	// Output
	outPcap := flag.String("w", "", "")
	rotateSize := flag.Uint64("rotate-size", 0, "")
	rotateTime := flag.Uint64("rotate-time", 0, "")
	csvOut := flag.String("csv", "", "")

	// Capture
	snaplen := flag.Uint("s", 65535, "")
	bufSize := flag.Uint("B", 0, "")
	promisc := flag.Bool("promisc", true, "")
	disableOffload := flag.Bool("disable-offload", false, "")

	flagV := flag.Bool("v", false, "")
	flagX := flag.Bool("x", false, "")
	flagXX := flag.Bool("X", false, "")
	flagxlink := flag.Bool("xx", false, "")
	flagXXlink := flag.Bool("XX", false, "")

	flagT := flag.Bool("t", false, "")
	flagTT := flag.Bool("tt", false, "")
	flagTTT := flag.Bool("ttt", false, "")
	flagTTTT := flag.Bool("tttt", false, "")

	// Misc
	disableDNS := flag.Bool("n", false, "")
	showStats := flag.Bool("stats", false, "")
	quiet := flag.Bool("q", false, "")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: tcpdump_go [options] [BPF expression]\n\n")
		fmt.Fprintf(os.Stderr, "Source:\n")
		fmt.Fprintf(os.Stderr, "  -i <iface>      Network interface (no -i: list available)\n")
		fmt.Fprintf(os.Stderr, "  -r <file>       Read from .pcap or .pcapng file\n")
		fmt.Fprintf(os.Stderr, "  -f <filter>     BPF filter, e.g. 'tcp port 443'\n")
		fmt.Fprintf(os.Stderr, "  -c <N>          Capture/process only N packets\n")
		fmt.Fprintf(os.Stderr, "\nOutput:\n")
		fmt.Fprintf(os.Stderr, "  -w <file>       Write packets to .pcap file\n")
		fmt.Fprintf(os.Stderr, "  -rotate-size N  Rotate -w file after N bytes\n")
		fmt.Fprintf(os.Stderr, "  -rotate-time N  Rotate -w file every N seconds\n")
		fmt.Fprintf(os.Stderr, "  -csv <file>     Write flows to CSV (only with -r)\n")
		fmt.Fprintf(os.Stderr, "\nCapture:\n")
		fmt.Fprintf(os.Stderr, "  -s <snaplen>    Max bytes per packet (default: 65535)\n")
		fmt.Fprintf(os.Stderr, "  -B <KB>         Kernel pcap buffer in KB (default: 2048 KB)\n")
		fmt.Fprintf(os.Stderr, "  -promisc        Promiscuous mode — enabled by default\n")
		fmt.Fprintf(os.Stderr, "  -disable-offload  Disable NIC offloading via ethtool (Linux, root)\n")
		fmt.Fprintf(os.Stderr, "\nView:\n")
		fmt.Fprintf(os.Stderr, "  -v              Verbose — more packet detail\n")
		fmt.Fprintf(os.Stderr, "  -x              Hex (no Ethernet header)\n")
		fmt.Fprintf(os.Stderr, "  -X              Hex + ASCII (no Ethernet header)\n")
		fmt.Fprintf(os.Stderr, "  -xx             Hex (with Ethernet header)\n")
		fmt.Fprintf(os.Stderr, "  -XX             Hex + ASCII (with Ethernet header)\n")
		fmt.Fprintf(os.Stderr, "\nTimestamp:\n")
		fmt.Fprintf(os.Stderr, "  -t              No timestamp\n")
		fmt.Fprintf(os.Stderr, "  -tt             Unix timestamp (seconds.microseconds)\n")
		fmt.Fprintf(os.Stderr, "  -ttt            Delta from previous packet\n")
		fmt.Fprintf(os.Stderr, "  -tttt           Date + time (2006-01-02 15:04:05.000000)\n")
		fmt.Fprintf(os.Stderr, "\nMisc:\n")
		fmt.Fprintf(os.Stderr, "  -n              Disable reverse DNS\n")
		fmt.Fprintf(os.Stderr, "  -stats          Print statistics summary on exit\n")
		fmt.Fprintf(os.Stderr, "  -q              Quiet mode — print only statistics (requires -stats)\n")
	}

	flag.Parse()
	if *csvOut != "" && *readPcap == "" {
		log.Fatal("-csv requires -r (read from pcap/pcapng file)")
	}
	const maxUint32 = 1<<32 - 1
	if *snaplen > maxUint32 {
		log.Fatalf("snaplen %d exceeds max uint32 (%d)", *snaplen, uint(maxUint32))
	}
	if *bufSize > maxUint32 {
		log.Fatalf("bufSize %d exceeds max uint32 (%d)", *bufSize, uint(maxUint32))
	}

	viewMode := "normal"
	switch {
	case *flagXXlink:
		viewMode = "hexascii_link"
	case *flagxlink:
		viewMode = "hex_link"
	case *flagXX:
		viewMode = "hexascii"
	case *flagX:
		viewMode = "hex"
	case *flagV:
		viewMode = "verbose"
	}

	tsMode := "default"
	switch {
	case *flagTTTT:
		tsMode = "tttt"
	case *flagTTT:
		tsMode = "ttt"
	case *flagTT:
		tsMode = "tt"
	case *flagT:
		tsMode = "t"
	}

	defer display.FlushOut()

	if *readPcap != "" {
		runReadPcap(*readPcap, *filter, *outPcap, viewMode, tsMode, *flagV, *disableDNS, *showStats, *quiet, *csvOut, *count)
	} else {
		capture.RunCapture(*iface, *filter, *outPcap, uint32(*snaplen), uint32(*bufSize), //#nosec G115 -- range checked above
			*promisc, *rotateSize, *rotateTime, viewMode, tsMode, *flagV, *disableDNS, *showStats, *quiet, *count, *disableOffload)
	}
}

// runReadPcap reads packets from a pcap/pcapng file, applies an optional BPF
// filter, prints each packet, and optionally writes to outPcap and csvOut.
func runReadPcap(pcapFile, filterExpr, outPcap, viewMode, tsMode string, verbose, disableDNS, showStats, quiet bool, csvOut string, count uint64) {
	f, reader := openPcapFile(pcapFile)

	// Compile BPF before registering defer — avoids exitAfterDefer (gocritic).
	var bpfFilter *pcap.BPF
	if filterExpr != "" {
		var err error
		bpfFilter, err = pcap.NewBPF(reader.LinkType(), 65535, filterExpr)
		if err != nil {
			_ = f.Close()
			log.Fatalf("invalid BPF filter %q: %v", filterExpr, err)
		}
	}

	var pw *rotation.PcapWriter
	if outPcap != "" {
		pw = rotation.NewPcapWriter(outPcap, 65535, reader.LinkType(), 0, 0)
		pw.Open()
	}

	defer func() {
		if pw != nil {
			pw.Close()
		}
		if err := f.Close(); err != nil {
			log.Printf("close file: %v", err)
		}
	}()

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	st := stats.NewStats()
	flowMap := make(map[flowKey]int)

	var pktNum uint64
	var prevTS time.Time
	for packet := range packetSource.Packets() {
		if bpfFilter != nil && !bpfFilter.Matches(packet.Metadata().CaptureInfo, packet.Data()) {
			continue
		}
		pktNum++
		ts := packet.Metadata().Timestamp
		if !quiet {
			display.PrintPacket(pktNum, packet, ts, prevTS, viewMode, tsMode, verbose, disableDNS)
		}
		prevTS = ts
		st.Update(packet)

		if pw != nil {
			pw.WritePacket(ts, packet.Data())
		}

		if csvOut != "" {
			proto, sport, dport := display.ExtractTransportInfo(packet)
			if sport != "" {
				if nl := packet.NetworkLayer(); nl != nil {
					src, dst := nl.NetworkFlow().Endpoints()
					k := flowKey{src.String(), dst.String(), sport, dport, proto}
					flowMap[k]++
				}
			}
		}

		if count > 0 && pktNum >= count {
			break
		}
	}

	display.FlushOut()

	if showStats {
		st.Print()
	}

	if csvOut != "" {
		writeCSV(csvOut, flowMap)
	}
}

// flowKey identifies a unique network flow: IP pair + ports + protocol.
type flowKey struct{ Src, Dst, Sport, Dport, Proto string }

// writeCSV writes aggregated flows to a CSV file.
func writeCSV(outFile string, flowMap map[flowKey]int) {
	f, err := os.Create(outFile) //#nosec G304 -- outFile comes from the -csv flag, not untrusted input
	if err != nil {
		log.Fatalf("cannot create CSV file: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("close CSV file: %v", cerr)
		}
	}()

	if _, err := fmt.Fprintln(f, "src_ip,dst_ip,src_port,dst_port,proto,count"); err != nil {
		log.Printf("write CSV header: %v", err)
		return
	}
	for k, cnt := range flowMap {
		if _, err := fmt.Fprintf(f, "%s,%s,%s,%s,%s,%d\n", k.Src, k.Dst, k.Sport, k.Dport, k.Proto, cnt); err != nil {
			log.Printf("write CSV row: %v", err)
			return
		}
	}
	display.Outf("%s %s\n", display.Colorize("CSV flows written:", display.ColorCyan), outFile)
	display.FlushOut()
}
