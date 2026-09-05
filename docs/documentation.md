# Documentation: tcpdump_go

> Generated from the working tree · Go 1.25.0 · toolchain go1.26.7

---

## CLI flags

```
Usage: tcpdump_go [options] [BPF expression]

Sources:
  -i interface       capture from an interface (name or -D number)
  -r file            read classic pcap or pcapng (- for stdin)
  -D                 list interfaces and exit
  -F file            read BPF expression from file
  -c N               stop after N matching packets

Raw output:
  -w file            write packets (default: do not print; - is stdout)
  --print            also print summaries with -w
  --pcapng           write pcapng and preserve mixed link types
  -C N               rotate classic pcap after N million bytes
  -G N               rotate classic pcap every N seconds
  -W N               limit rotation to N files (cyclic with -C, stop with -G)
  -U                 flush each raw packet to storage

Presentation:
  -q                 quick output (tcpdump semantics; not silent)
  -v, -vv, -vvv      verbose protocol details; more detail each level
  -A                 ASCII; -x/-X hex; -xx/-XX include link header
  -e                 print link-layer header
  -S                 absolute TCP sequence numbers
  -# / --number      print packet numbers
  -t/-tt/-ttt/-tttt  timestamp modes
  -n                 do not resolve host names; -nn also leaves ports numeric
  -f                 print foreign addresses numerically
  -l                 flush text output after every packet

Capture and extensions:
  -s N               snapshot length (default 262144)
  -B N               kernel buffer in KiB
  -p                 disable promiscuous mode
  -Z user            drop privileges to user once the source is open
  --immediate-mode   deliver packets as they arrive; off for silent -w
  --disable-offload  temporarily disable and restore Linux NIC offloads
  --stats            extended session statistics
  --stats-only       statistics without packet lines
  --count            count matching packets
  --csv file         aggregate offline flows
  --color mode       auto, always, or never
  --version          print version and exit

Legacy aliases (the tcpdump spellings above are preferred):
  --filter expr      BPF expression; use the positional form instead
  --promisc          promiscuous mode, on by default; -p turns it off
  --rotate-size N    rotate the -w file after N bytes (-C uses millions)
  --rotate-time N    rotate the -w file every N seconds (same as -G)
```

## Packages


### `capture`

```
package capture // import "tcpdump_go/capture"

Package capture handles live network packet capture via libpcap: opening
interfaces, listing available interfaces, and signal handling.

VARIABLES

var ErrNotPrivileged = errors.New("not running as root, so there are no privileges to drop")
    ErrNotPrivileged reports that -Z was asked for by a process that is not
    root. tcpdump treats that as a no-op because there is nothing to drop,
    so callers warn and carry on rather than failing.

var ShutdownSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
    ShutdownSignals lists the OS signals that trigger a graceful capture
    shutdown. SIGHUP is here because an unhandled one skips the deferred offload
    restore. SIGQUIT is left out so it still dumps goroutines.


FUNCTIONS

func DisableOffloading(iface string) (func() error, error)
    DisableOffloading disables mutable receive/transmit offloads and returns an
    idempotent restoration closure. The caller must invoke the closure on every
    path after success because ethtool settings are global to the interface.

func DropPrivileges(username string) error
    DropPrivileges implements tcpdump's -Z. Call it after the handle is active
    (the only step needing root) and before creating output files, so captures
    are owned by the target user. A partial drop is an error, not a success.

func OpenHandle(iface string, snaplen, bufSize uint32, promisc, immediate bool) (*pcap.Handle, error)
    OpenHandle opens a pcap handle on iface with the given snaplen, buffer
    size (KB), promiscuous-mode, and immediate-delivery settings. A finite
    read timeout makes signal-driven shutdown safe without closing a handle
    concurrently with a blocked read.

func PrintInterfaces(verbosity int) error
    PrintInterfaces lists all network interfaces available to libpcap.

func ResolveInterface(value string) (string, error)
    ResolveInterface maps a -i value to a device name. tcpdump accepts the index
    printed by -D, so "2" selects the second device in that same listing.

func RunCapture(cfg Config) (retErr error)
    RunCapture starts a live packet capture and processes packets until Ctrl+C
    / SIGTERM, or until cfg.Count packets have been seen (0 = unlimited).
    All resources are closed and already captured packets are processed before
    the function returns.


TYPES

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
    Config holds all parameters for a live packet capture session.
```

### `display`

```
package display // import "tcpdump_go/display"

Package display provides packet formatting and output utilities: ANSI colors,
buffered output, a bounded DNS cache, hex dumps, and packet header formatting.

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

var UseColor bool
    UseColor controls whether output includes ANSI escape codes.


FUNCTIONS

func AppendOffset(buf []byte, i int) []byte
    AppendOffset appends a hexadecimal offset to buf, padded to at least four
    digits. Unlike a fixed-width implementation it does not wrap after 64 KiB.

func CaptureOut() (*bytes.Buffer, func())
    CaptureOut redirects Out to an in-memory buffer; returns the buffer and a
    restore function. It is intended for tests and should not race with live
    packet rendering.

func ClearDNSCache(ip string)
    ClearDNSCache removes ip from the reverse-DNS cache. Passing an empty string
    clears the complete cache, which is useful between capture sessions.

func Colorize(s, color string) string
    Colorize wraps s in the given ANSI color code; no-op when UseColor is false.

func ConfigureRenderer(options RenderOptions)
    ConfigureRenderer applies options to the default printer and clears its
    relative TCP sequence state.

func ExtractPorts(tl gopacket.TransportLayer) (sport, dport string)
    ExtractPorts returns source/destination ports for port-bearing transports.

func ExtractTransportInfo(packet gopacket.Packet) (proto, sport, dport string)
    ExtractTransportInfo returns protocol name and source/destination ports.

func FlushOut() error
    FlushOut flushes the buffered output writer. Returning the error lets the
    caller distinguish successful capture from partial output (for example,
    on a full disk or a closed pipe).

func FormatTS(ts, prevTS time.Time, mode TSMode) string
func IPLayerName(nl gopacket.NetworkLayer) string
    IPLayerName returns tcpdump's short IP layer name.

func Outf(format string, args ...any) error
    Outf writes a formatted string to Out and reports an immediate or
    line-buffer flush error. A final FlushOut still needs to be checked when
    normal buffering is enabled.

func Outln(args ...any) error
    Outln writes args followed by a newline to Out.

func PacketPayload(packet gopacket.Packet) []byte
    PacketPayload returns packet data above the link layer.

func PrintASCII(data []byte) error
    PrintASCII prints packet bytes in a terminal-safe ASCII form (-A style).
    Control and non-ASCII bytes become dots, and long packets are wrapped to
    keep each output line readable.

func PrintHex(data []byte) error
    PrintHex prints data as a hex dump (-x style) to Out.

func PrintHexASCII(data []byte) error
    PrintHexASCII prints data as hex+ASCII (-X style) to Out.

func PrintNormal(num uint64, packet gopacket.Packet, tsStr string, disableDNS bool) error
    PrintNormal prints a compact one-line packet summary.

func PrintPacket(num uint64, packet gopacket.Packet, ts, prevTS time.Time, viewMode ViewMode, tsMode TSMode, verbosity int, disableDNS bool) error
    PrintPacket dispatches packet rendering based on viewMode and tsMode.

func PrintVerbose(num uint64, packet gopacket.Packet, tsStr string, verbosity int, disableDNS bool) error
    PrintVerbose prints IP metadata followed by the protocol summary.

func ResetOutput() error
    ResetOutput restores buffered stdout output.

func ResetRenderer()
    ResetRenderer restores the package defaults and clears per-flow state.

func ResolveIP(ip string) string
    ResolveIP schedules a time-bounded reverse DNS lookup and immediately
    returns a cached name or the numeric address. Resolution is deliberately
    off the capture/render path, so a slow resolver cannot cause kernel packet
    drops.

func ResolveIPContext(ctx context.Context, ip string) string
    ResolveIPContext avoids scheduling new work when ctx is already cancelled.
    Lookups themselves use the package timeout because they continue in a
    bounded worker after this non-blocking function returns.

func SetOutput(w io.Writer, bufferSize int) error
    SetOutput directs subsequent display output to w. A positive bufferSize
    enables normal buffering. A bufferSize <= 0 flushes after every display
    write, which is useful for line-oriented terminal or stderr output.

    SetOutput flushes the previous writer first and returns that flush error.
    Configuration is intended to happen before packet rendering starts.

func TCPFlagsShort(tcp *layers.TCP) string
    TCPFlagsShort returns tcpdump's TCP flag notation.

func TCPOptionsStr(tcp *layers.TCP) string
    TCPOptionsStr formats TCP options as a comma-separated string.


TYPES

type Printer struct {
	// Has unexported fields.
}
    Printer owns one output stream and the render state of a single capture
    session: presentation options and per-flow TCP sequence bases. The
    package-level functions delegate to defaultPrinter.

    Colour is deliberately not here: it describes the terminal, not a session.

func NewPrinter(w io.Writer, bufferSize int) *Printer
    NewPrinter returns a Printer writing to w. A bufferSize of zero or less
    flushes after every write, which is what line-oriented output needs.

func (p *Printer) Capture() (*bytes.Buffer, func())
    Capture redirects the printer into a buffer and returns a restore function.
    Holding a Printer means a test can read its own output instead of swapping
    process-wide state.

func (p *Printer) Configure(options RenderOptions)
    Configure applies options and drops relative TCP sequence state, which
    belongs to the previous session.

func (p *Printer) Flush() error
    Flush empties the buffer. The error distinguishes a complete capture from
    partial output on a full disk or closed pipe.

func (p *Printer) Outf(format string, args ...any) error
    Outf writes a formatted line.

func (p *Printer) Outln(args ...any) error
    Outln writes args followed by a newline.

func (p *Printer) Reset()
    Reset restores the package defaults and clears per-flow state.

func (p *Printer) SetOutput(w io.Writer, bufferSize int) error
    SetOutput redirects the printer, flushing the previous writer and returning
    that flush error.

func (p *Printer) Write(b []byte) error
    Write emits raw bytes, honouring the flush-every-write setting.

type RenderOptions struct {
	LinkHeader              bool // -e
	ShowPacketNumber        bool // -# / --number
	AbsoluteSequenceNumbers bool // -S
	NumericPorts            bool // -n/-nn
}
    RenderOptions controls tcpdump-compatible presentation details that apply to
    a complete capture session.

type TSMode uint8
    TSMode controls how the packet timestamp is rendered.

const (
	TSDefault  TSMode = iota // HH:MM:SS.micros
	TSNone                   // -t
	TSUnix                   // -tt
	TSDelta                  // -ttt
	TSDateTime               // -tttt
)
    Recognized TSMode values.

type ViewMode uint8
    ViewMode controls the format used when printing a packet.

const (
	ViewNormal       ViewMode = iota // default one-line summary
	ViewVerbose                      // -v
	ViewHex                          // -x
	ViewHexASCII                     // -X
	ViewHexLink                      // -xx
	ViewHexASCIILink                 // -XX
	ViewQuick                        // -q: shorter one-line summary
	ViewASCII                        // -A: safe ASCII above the link layer
)
    Recognized ViewMode values.
```

### `offline`

```
package offline // import "tcpdump_go/offline"

Package offline provides lossless, explicit-error pcap and pcapng I/O.

TYPES

type NgWriter struct {
	// Has unexported fields.
}
    NgWriter writes pcapng while retaining per-packet wire length, timestamp,
    and differing link types. It deliberately never closes stdout.

func NewNgWriter(path string) *NgWriter
    NewNgWriter returns a writer for path; "-" writes to stdout. The stream is
    created by Open, not here.

func (w *NgWriter) Close() error
    Close flushes the pcapng stream and closes its file. It is idempotent.

func (w *NgWriter) Flush() error
    Flush makes all buffered pcapng blocks visible without closing the stream.

func (w *NgWriter) Open(linkType layers.LinkType, snaplen uint32) error
    Open creates a section and its first interface.

func (w *NgWriter) WritePacket(ci gopacket.CaptureInfo, data []byte, linkType layers.LinkType, snaplen uint32) error
    WritePacket adds an interface descriptor as needed and writes one packet.

type Reader struct {
	// Has unexported fields.
}
    Reader reads classic pcap and pcapng, including gzip-compressed streams.
    For pcapng it preserves every interface/link type instead of silently
    skipping packets whose type differs from the first interface.

func Open(path string) (*Reader, error)
    Open opens path. A path of "-" reads from stdin without closing it.

func OpenReader(input io.Reader, name string) (*Reader, error)
    OpenReader reads a capture from an already-open stream. name only labels
    error messages; the stream is not closed by Close.

func (r *Reader) Close() error
    Close closes decompression and file resources. stdin is never closed.

func (r *Reader) Interface(index int) (pcapgo.NgInterface, error)
    Interface returns metadata for the current pcapng section/interface.

func (r *Reader) IsNg() bool
    IsNg reports whether the input is pcapng.

func (r *Reader) LinkType() layers.LinkType
    LinkType returns the classic pcap link type. For mixed pcapng, callers must
    use the per-packet value returned by ReadPacketData.

func (r *Reader) PacketSnaplen(ci gopacket.CaptureInfo) uint32
    PacketSnaplen returns the header/interface snap length applicable to ci.

func (r *Reader) ReadPacketData() (packet []byte, info gopacket.CaptureInfo, link layers.LinkType, retErr error)
    ReadPacketData reads one record and reports the record's actual link type.
    io.EOF means clean end-of-file; io.ErrUnexpectedEOF and all other errors
    indicate a malformed or failed input and must not be treated as success.

func (r *Reader) Snaplen() uint32
    Snaplen returns the classic pcap header snap length. pcapng can have one
    value per interface, so zero is returned and callers should choose a safe
    value from the packets they write.
```

### `rotation`

```
package rotation // import "tcpdump_go/rotation"

Package rotation implements pcap file writing with size- and time-based rotation
(PcapWriter).

VARIABLES

var ErrFileLimitReached = errors.New("rotation file limit reached")
    ErrFileLimitReached reports that -W's file count was reached while rotating
    on time. tcpdump ends the capture there, so callers treat it as a clean stop
    rather than a failure.


TYPES

type PcapWriter struct {
	// Has unexported fields.
}
    PcapWriter writes packets to a pcap file with optional size- and time-based
    rotation. A baseFile of "-" writes an unrotated pcap stream to stdout.

func NewPcapWriter(baseFile string, snaplen uint32, lt layers.LinkType, rotateSize, rotateTime uint64) *PcapWriter
    NewPcapWriter creates a PcapWriter; rotation by size (bytes) or time
    (seconds) is disabled when the respective value is zero.

func (pw *PcapWriter) Close() error
    Close flushes and closes the current output file. stdout is flushed but is
    deliberately never closed. Close is idempotent.

func (pw *PcapWriter) Filename() string
    Filename returns the current file path (_NNN suffix for rotated segments).

func (pw *PcapWriter) Flush() error
    Flush makes all currently buffered pcap records visible to the underlying
    file or stream without closing it. It implements tcpdump's -U behaviour.

func (pw *PcapWriter) Open() error
    Open creates the output file and writes its pcap header. It is a no-op when
    baseFile is empty. A baseFile of "-" writes to stdout; rotating stdout is
    rejected because a pcap stream cannot contain multiple file headers.

func (pw *PcapWriter) SetMaxFiles(n uint64)
    SetMaxFiles applies tcpdump's -W. With size rotation the segments form a
    rotating buffer of n files; with time rotation the capture stops once n
    files exist, which is what tcpdump does for each case.

func (pw *PcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error
    WritePacket appends a packet, rotating the file before it when adding the
    packet would exceed a configured limit. CaptureLength is normalized to the
    actual data size and Length is raised when necessary; all other CaptureInfo
    fields, including Timestamp and the original wire Length, are preserved.
    A source record without a timestamp is mapped deterministically to the Unix
    epoch because classic pcap cannot represent an absent timestamp.
```

### `stats`

```
package stats // import "tcpdump_go/stats"

Package stats collects and prints capture session statistics: protocol counters,
packet sizes, TCP flags, and top senders/ports.

FUNCTIONS

func Pct(part, total uint64) string
    Pct returns "X.X%" for part/total, or "—" when total is zero.

func TopN[K comparable](m map[K]uint64, n int) []string
    TopN returns the top n entries from m, sorted by value descending. Keys are
    formatted here rather than on the counting path, which is why the counters
    can use allocation-free key types.


TYPES

type Stats struct {
	Total     uint64
	Bytes     uint64 // captured bytes; retained for API compatibility
	WireBytes uint64
	// Dropped is filled in from libpcap once the capture loop has finished.
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

	TCPSYN uint64
	TCPFIN uint64
	TCPRST uint64

	FirstPkt time.Time
	LastPkt  time.Time

	// SrcIPCount is keyed by gopacket's endpoint value, so counting a packet
	// costs no string allocation; only the printed entries are formatted.
	SrcIPCount map[gopacket.Endpoint]uint64
	// UntrackedSrcIPs counts packets whose source was not recorded because the
	// address table was already full.
	UntrackedSrcIPs uint64
	// DstPortCount is keyed by port number, which bounds it at 64Ki entries.
	DstPortCount map[uint16]uint64
}
    Stats holds per-session capture counters and histograms.

func NewStats() *Stats
    NewStats returns a zeroed Stats ready for use.

func (s *Stats) Print() error
    Print writes the session summary to buffered output.

func (s *Stats) Update(packet gopacket.Packet)
    Update increments counters from packet. Not goroutine-safe.
```


## Platform-specific files

| File | Build tag | Description |
|------|-----------|-------------|
| `offload_linux.go` | `linux` | ethtoolFeature maps the stable feature name printed by `ethtool -k` to the |
| `offload_other.go` | `!linux` | DisableOffloading is explicit on unsupported systems: silently accepting |
| `privileges_unix.go` | `!windows` | DropPrivileges implements tcpdump's -Z. Call it after the handle is active |
| `privileges_windows.go` | `windows` | DropPrivileges is explicit on Windows: silently ignoring -Z would promise a |
| `signals_unix.go` | `!windows` | ShutdownSignals lists the OS signals that trigger a graceful capture shutdown. |
| `signals_windows.go` | `windows` | ShutdownSignals lists the OS signals that trigger a graceful capture shutdown. |

## Dependencies

```
github.com/gopacket/gopacket v1.7.1
github.com/vishvananda/netlink v1.1.0
github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
golang.org/x/crypto v0.51.0
golang.org/x/net v0.55.0
golang.org/x/sys v0.45.0
golang.org/x/term v0.43.0
golang.org/x/text v0.37.0
```

## Code metrics

| Metric | Value |
|--------|-------|
| .go files | 44 |
| Total lines | 10654 |
| Code lines | 9031 |
| Comment lines | 790 |
