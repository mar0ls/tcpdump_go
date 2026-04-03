# Documentation: tcpdump_go
> Generated: 2026-04-03 21:15:22 · commit: n/a · Go 1.25.0

---
## Package description
tcpdump_go — network packet analyzer built on libpcap and gopacket. Supports
live capture, pcap/pcapng file reading, BPF filters, file rotation, flow CSV
export, and colorized output. Requires root or CAP_NET_RAW.

## CLI flags
```
Usage: tcpdump_go [options] [BPF expression]

Source:
  -i <iface>      Network interface (no -i: list available)
  -r <file>       Read from .pcap or .pcapng file
  -f <filter>     BPF filter, e.g. 'tcp port 443'
  -c <N>          Capture/process only N packets

Output:
  -w <file>       Write packets to .pcap file
  -rotate-size N  Rotate -w file after N bytes
  -rotate-time N  Rotate -w file every N seconds
  -csv <file>     Write flows to CSV (only with -r)

Capture:
  -s <snaplen>    Max bytes per packet (default: 65535)
  -B <KB>         Kernel pcap buffer in KB (default: 2048 KB)
  -promisc        Promiscuous mode — enabled by default
  -disable-offload  Disable NIC offloading via ethtool (Linux, root)

View:
  -v              Verbose — more packet detail
  -x              Hex (no Ethernet header)
  -X              Hex + ASCII (no Ethernet header)
  -xx             Hex (with Ethernet header)
  -XX             Hex + ASCII (with Ethernet header)

Timestamp:
  -t              No timestamp
  -tt             Unix timestamp (seconds.microseconds)
  -ttt            Delta from previous packet
  -tttt           Date + time (2006-01-02 15:04:05.000000)

Misc:
  -n              Disable reverse DNS
  -stats          Print statistics summary on exit
  -q              Quiet mode — print only statistics (requires -stats)
```

## Sub-packages

### `capture`

```go
package capture // import "tcpdump_go/capture"

Package capture handles live network packet capture via libpcap: opening
interfaces, listing available interfaces, and signal handling.

VARIABLES

var ShutdownSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}
    ShutdownSignals lists the OS signals that trigger a graceful capture
    shutdown.


FUNCTIONS

func DisableOffloading(iface string)
func OpenHandle(iface string, snaplen, bufSize uint32, promisc bool) *pcap.Handle
    OpenHandle opens an activated pcap handle for iface with the specified
    snaplen and buffer size (KB). It enables promiscuous mode if promisc is true
    and sets immediate mode for low-latency delivery.

func PrintInterfaces()
    PrintInterfaces lists all network interfaces available to libpcap and exits.

func RunCapture(
	iface, filter, outPcap string,
	snaplen, bufSize uint32,
	promisc bool,
	rotateSize, rotateTime uint64,
	viewMode, tsMode string,
	verbose, disableDNS, showStats, quiet bool,
	count uint64,
	disableOffload bool,
)
    RunCapture starts a live packet capture on iface and processes packets until
    Ctrl+C (or SIGTERM), or until count packets have been seen (0 = unlimited).
    Captured packets are decoded, optionally written to outPcap, and displayed
    according to viewMode/tsMode. Statistics are printed if showStats is true.
```

### `display`

```go
package display // import "tcpdump_go/display"

Package display provides packet formatting and output utilities: ANSI colors,
buffered stdout, DNS cache, hex dumps, and header formatting.

CONSTANTS

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
)
    ANSI escape codes for terminal colorization.


VARIABLES

var Out = bufio.NewWriterSize(os.Stdout, 256*1024)
    Out is the buffered stdout writer (256 KB). Batches small writes into a
    single syscall.

var UseColor bool
    UseColor controls whether output includes ANSI escape codes.


FUNCTIONS

func AppendOffset(buf []byte, i int) []byte
    AppendOffset appends a 4-digit zero-padded hex offset to buf and returns the
    result.

func CaptureOut() (*bytes.Buffer, func())
    CaptureOut redirects Out to an in-memory buffer and returns the buffer and a
    restore function. Used in tests to capture printed output.

func ClearDNSCache(ip string)
    ClearDNSCache removes ip from the reverse-DNS cache.

func Colorize(s, color string) string
    Colorize wraps s in the given ANSI color code. Returns s unchanged when
    UseColor is false (e.g. stdout is not a terminal).

func ExtractPorts(tl gopacket.TransportLayer) (sport, dport string)
    ExtractPorts returns the source and destination port strings for a TCP or
    UDP transport layer. Returns empty strings for other layer types.

func ExtractTransportInfo(packet gopacket.Packet) (proto, sport, dport string)
    ExtractTransportInfo returns the protocol name, source port, and destination
    port for a packet. Used to build flow keys for CSV export.

func FlushOut()
    FlushOut flushes the buffered stdout writer. Call after writing a logical
    batch of output to avoid stale data in the buffer.

func FormatTS(ts, prevTS time.Time, mode string) string
    FormatTS formats a packet timestamp according to mode: "t" = none,
    "tt" = unix epoch, "ttt" = delta from prevTS, "tttt" = date+time, default =
    HH:MM:SS.micros.

func IpLayerName(nl gopacket.NetworkLayer) string
    IpLayerName returns "IP", "IP6", or the raw layer type string for nl.

func Outf(format string, args ...any)
    Outf writes a formatted string to the buffered stdout writer.

func Outln(args ...any)
    Outln writes args followed by a newline to the buffered stdout writer.

func PacketPayload(packet gopacket.Packet) []byte
    PacketPayload returns the packet bytes above the link layer (i.e. the
    network layer and above). Falls back to the full raw data if no link layer
    is present.

func PrintHex(data []byte)
    PrintHex prints data as a hex dump (without ASCII column) to Out. Each row
    shows a 4-hex-digit offset followed by up to 16 bytes in hex.

func PrintHexASCII(data []byte)
    PrintHexASCII prints data as a hex+ASCII dump to Out (tcpdump -X style).
    Each row shows offset, hex bytes, and a printable-ASCII column.

func PrintNormal(num uint64, packet gopacket.Packet, tsStr string, disableDNS bool)
    PrintNormal prints a compact one-line packet summary (default tcpdump
    style).

func PrintPacket(num uint64, packet gopacket.Packet, ts, prevTS time.Time, viewMode, tsMode string, verbose, disableDNS bool)
    PrintPacket dispatches packet rendering to the appropriate sub-printer
    based on viewMode ("normal", "verbose", "hex", "hexascii", "hex_link",
    "hexascii_link").

func PrintVerbose(num uint64, packet gopacket.Packet, tsStr string, disableDNS bool)
    PrintVerbose prints a detailed one- or two-line packet summary (tcpdump -v
    style) with IP metadata, TCP flags, sequence numbers, and options.

func ResolveIP(ip string) string
    ResolveIP performs a reverse DNS lookup for ip and caches the result.
    Returns the original IP string on failure or when no PTR record exists.

func TcpFlagsShort(tcp *layers.TCP) string
    TcpFlagsShort returns an abbreviated TCP flag string, e.g. "SA", "F", "R".

func TcpOptionsStr(tcp *layers.TCP) string
    TcpOptionsStr returns a comma-separated string of TCP options (MSS,
    timestamps, window scale, SACK). Unknown option kinds are rendered as
    "opt-N".
```

### `rotation`

```go
package rotation // import "tcpdump_go/rotation"

Package rotation implements pcap file writing with size- and time-based rotation
(PcapWriter).

TYPES

type PcapWriter struct {
	// Has unexported fields.
}
    PcapWriter writes packets to a pcap file with optional size- and time-based
    rotation. When rotation triggers, the current file is closed and a new one
    is opened with a numeric suffix (e.g. capture_001.pcap).

func NewPcapWriter(baseFile string, snaplen uint32, lt layers.LinkType, rotateSize, rotateTime uint64) *PcapWriter
    NewPcapWriter creates a PcapWriter for baseFile. rotateSize triggers
    rotation after that many bytes (0 = disabled); rotateTime triggers rotation
    after that many seconds (0 = disabled). Call Open before writing any
    packets.

func (pw *PcapWriter) Close()
    Close flushes and closes the current output file.

func (pw *PcapWriter) Filename() string
    Filename returns the path of the current output file. For the first segment
    it returns baseFile unchanged; subsequent segments get a _NNN suffix.

func (pw *PcapWriter) Open()
    Open creates the current output file and writes the pcap global header.
    It is a no-op when baseFile is empty.

func (pw *PcapWriter) WritePacket(ts time.Time, data []byte)
    WritePacket appends a packet to the current output file, rotating if the
    configured size or time limit has been reached.
```

### `stats`

```go
package stats // import "tcpdump_go/stats"

Package stats collects and prints capture session statistics: protocol counters,
packet sizes, TCP flags, and top senders/ports.

FUNCTIONS

func Pct(part, total uint64) string
    Pct returns "X.X%" for part/total, or "—" when total is zero.

func TopN(m map[string]uint64, n int) []string
    TopN returns the n keys from m with the highest values, formatted as "key
    count" (left-padded to 20 chars).


TYPES

type Stats struct {
	Total uint64
	Bytes uint64
	// Dropped is updated from the signal goroutine — always access via .Load()/.Store().
	Dropped atomic.Uint64

	IPv4    uint64
	IPv6    uint64
	ARP     uint64
	OtherL3 uint64

	TCP     uint64
	UDP     uint64
	ICMP    uint64
	OtherL4 uint64

	MinSize uint64
	MaxSize uint64
	SumSize uint64

	TcpSYN uint64
	TcpFIN uint64
	TcpRST uint64

	FirstPkt time.Time
	LastPkt  time.Time

	SrcIPCount   map[string]uint64
	DstPortCount map[string]uint64
}
    Stats holds per-session capture counters and histograms.

func NewStats() *Stats
    NewStats returns a zero-initialised Stats with the map fields allocated.

func (s *Stats) Print()
    Print writes the full session summary (duration, packet counts, protocol
    breakdown, top senders, top destination ports) to the buffered output.

func (s *Stats) Update(packet gopacket.Packet)
    Update extracts layer information from packet and increments the appropriate
    counters. Must not be called concurrently.
```

## Dependencies
```
github.com/google/gopacket v1.1.19
golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
golang.org/x/lint v0.0.0-20200302205851-738671d3881b
golang.org/x/mod v0.1.1-0.20191105210325-c90efee705ee
golang.org/x/net v0.0.0-20190620200207-3b0461eec859
golang.org/x/sync v0.0.0-20190423024810-112230192c58
golang.org/x/sys v0.0.0-20190412213103-97732733099d
golang.org/x/text v0.3.0
golang.org/x/tools v0.0.0-20200130002326-2f3ba24bd6e7
golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
```

## Code metrics
| Metric | Value |
|--------|-------|
| .go files | 16 |
| Total lines | 3521 |
| Code lines | 2974 |
| Comment lines | 200 |
