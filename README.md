# tcpdump_go

Network packet analyzer written in Go on top of libpcap and
[gopacket](https://github.com/gopacket/gopacket).

The CLI follows tcpdump for its core capture workflow and adds safe pcapng
rewriting, rotation, flow CSV, color, and extended statistics. It is not yet a
drop-in implementation of every tcpdump protocol printer or flag; unsupported
combinations fail explicitly instead of silently discarding data.

## Requirements

- Go 1.25+ (the module selects the patched Go 1.26.7 toolchain by default)
- libpcap (`sudo apt install libpcap-dev` or `brew install libpcap`)
- root or the appropriate capture capability for live traffic
- Npcap on Windows

## Build and test

```bash
go build -o tcpdump_go .
go test ./...
go test -race ./...
```

## Quick start

```bash
# No source lists interfaces and exits successfully; -D is the explicit form.
./tcpdump_go
./tcpdump_go -D

# Standard positional BPF expression.
sudo ./tcpdump_go -i eth0 -nn -c 100 'tcp port 443'

# Read either classic pcap or pcapng.
./tcpdump_go -r capture.pcapng -nn 'udp or icmp'

# Like tcpdump, -w writes raw packets and suppresses packet text by default.
sudo ./tcpdump_go -i eth0 -w capture.pcap 'not port 22'

# Request text as well as raw output.
sudo ./tcpdump_go -i eth0 -w capture.pcap --print -q
```

Run `./tcpdump_go -h` for the authoritative flag list.

## Tcpdump-compatible core flags

| Flag | Meaning |
| --- | --- |
| `-i interface` | live capture source: a name, or the number shown by `-D` |
| `-r file` | classic pcap or pcapng input; `-` is stdin |
| `-D` | list interfaces, numbered as tcpdump does |
| `expression` | positional BPF expression |
| `-F file` | read a BPF expression from a file |
| `-c N` | stop after N matching packets |
| `-w file` | raw packet output; `-` is stdout |
| `--print` | print summaries while using `-w` |
| `-C N` | rotate classic pcap after N million bytes |
| `-G N` | rotate classic pcap every N seconds |
| `-W N` | limit rotation to N files: cyclic with `-C`, stop with `-G` |
| `-U` | flush each packet written by `-w` |
| `-s N`, `-B N`, `-p` | snap length, buffer KiB, non-promiscuous mode |
| `-q`, `-v`, `-vv`, `-vvv` | quick, or verbose with increasing detail |
| `-A`, `-x`, `-X`, `-xx`, `-XX` | ASCII/hex views |
| `-e` | link-layer header |
| `-S` | absolute TCP sequence numbers |
| `-#`, `--number` | packet numbers |
| `-t`, `-tt`, `-ttt`, `-tttt` | timestamp modes |
| `-n`, `-nn` | numeric addresses/ports |
| `-f` | print foreign addresses numerically |
| `-l` | flush text after every packet |
| `-Z user` | drop privileges once the capture source is open |

Short flags combine the way getopt allows: boolean clusters such as `-nXX`,
`-nv`, and `-ntttt`, and a trailing value flag that takes either a glued or a
separate value — `-c100`, `-nni eth0`, `-s96`.

### Application-layer output

DNS and HTTP get tcpdump's own printers. Output is unwrapped; these lines are
verbatim:

```
IP 192.168.1.10.55555 > 8.8.8.8.53: 4660+ A? example.com. (29)
IP 192.168.1.10.44321 > 93.184.216.34.80: Flags [P.], seq 1000:1071, ack 1, win 502, length 71: HTTP: GET /index.html HTTP/1.1
```

Each level adds detail: `-v` verifies TCP and IP checksums and names DNS
records, `-vv` adds the UDP checksum and echoes the DNS question, `-vvv` adds
record TTLs. `TestByteForByteParityWithTcpdump` diffs the whole output against
the system tcpdump for every fixture at every level.

A live capture ends with tcpdump's counters on stderr:

```
1240 packets captured
1256 packets received by filter
16 packets dropped by kernel
```

The historical `--filter 'tcp port 443'` extension remains available, but the
positional form is preferred. `-F` has tcpdump's filter-file meaning.

## Extensions

```bash
# Preserve multiple pcapng interfaces/link types.
./tcpdump_go -r mixed.pcapng -w copy.pcapng --pcapng

# Classic-pcap rotation in byte units (alternative to -C/-G).
sudo ./tcpdump_go -i eth0 -w capture.pcap \
  --rotate-size 104857600 --rotate-time 3600

# Extended statistics without packet lines.
./tcpdump_go -r capture.pcap --stats-only

# Count matching packets.
./tcpdump_go -r capture.pcap --count 'tcp port 443'

# Deterministic, atomically published flow CSV.
./tcpdump_go -r capture.pcap --csv flows.csv

# Disable mutable Linux offloads only for the capture lifetime.
sudo ./tcpdump_go -i eth0 --disable-offload

# Open the interface as root, then run as nobody for the rest of the session.
# Output files are created after the switch, so they belong to that user.
sudo ./tcpdump_go -i eth0 -Z nobody -w capture.pcap

# Trade latency for throughput on a saturated link.
sudo ./tcpdump_go -i eth0 --immediate-mode=false -w capture.pcap
```

`-Z` cannot be combined with `--disable-offload`: restoring the NIC settings
needs exactly the privileges `-Z` gives away, so the pair is rejected instead
of leaving the interface changed.

Run without root, `-Z` has nothing to drop. tcpdump silently ignores it there;
this tool does the same but says so on stderr, so a skipped hardening step is
never mistaken for a completed one. A misspelled account stays a hard error.

Other extensions include `--color auto|always|never`, the byte/second rotation
aliases `--rotate-size` and `--rotate-time`, and the legacy `--promisc`
(promiscuous mode is on by default; `-p` turns it off).

## Data-fidelity guarantees

- Offline reads use explicit `ReadPacketData` loops. A truncated or corrupt
  record returns a non-zero exit status instead of looking like clean EOF.
- Rewriting preserves the packet timestamp, captured length, original wire
  length, source snap length, and nanosecond precision. Records whose source
  format has no timestamp use the Unix epoch when the target record requires
  one; they never acquire the current wall-clock time.
- pcapng is read with mixed-link support. Writing `.pcapng` creates interface
  descriptors as link types appear. Writing mixed links to classic pcap returns
  an error rather than dropping packets.
- Input, raw output, CSV output, hard-link aliases, symlinks, and future rotated
  filenames are checked before any output is created.
- Write, flush, close, CSV, and terminal errors reach the process exit status.
- `-w -` is a clean binary stream: human-readable output and diagnostics are
  kept off stdout.

## Packet presentation

The built-in renderer currently covers Ethernet/VLAN, ARP, IPv4, IPv6, TCP,
UDP, ICMPv4/v6, SCTP, IP fragments, and unknown IP protocol numbers, plus the
DNS and HTTP application printers. It shows tcpdump-style TCP flags and
relative sequence numbers by default.

Malformed headers are never rendered from zero-filled partial structs. They
produce markers such as `[|ether]`, `[|ip]`, or `[|tcp]`; application decoder
failures remain visible as invalid/decode-error annotations. IP lengths exclude
Ethernet padding, and IPv4 fragment offsets are converted to byte units.

Reverse DNS is numeric-first and asynchronous. Four bounded workers start on
the first lookup — a run with `-n`, `-w`, or `--version` never starts them —
and use short timeouts with a bounded TTL/LRU cache, so a slow resolver cannot
block packet consumption. Use `-n` for deterministic numeric output.

## Statistics

`--stats` adds a session report; `--stats-only` suppresses packet lines. The
report distinguishes captured bytes from original wire bytes and includes
protocol counts, size distribution, TCP flags, top senders/ports, throughput,
and kernel drops. The address table is capped, and packets from addresses past
that cap are reported as a separate count so the totals stay honest. Live kernel statistics are collected after `-c` as well as
after signal-driven shutdown.

## Live-capture lifecycle

The libpcap handle uses a finite read timeout. SIGINT, SIGTERM, and SIGHUP
cancel the owned read loop; already queued packets are drained, output is
flushed, kernel drop statistics are collected, and only then are resources
closed. This avoids the idle-interface deadlock caused by closing a handle
concurrently with a blocked libpcap read. SIGHUP is handled because closing a
terminal would otherwise skip the deferred restoration of NIC offloads;
SIGQUIT is deliberately left to Go's stack dump.

On Linux, `--disable-offload` queries mutable `ethtool` state after the handle,
BPF, and output have been validated. It disables checksum, segmentation,
receive aggregation (including LRO/hardware GRO where exposed), scatter/gather,
and VLAN receive offloads, then restores every changed setting on exit. The
flag fails explicitly on unsupported platforms.

## Streams

| Stream | Content |
| --- | --- |
| stdout | packet text, interface list, `--count`, or statistics without raw output |
| stderr | status, statistics accompanying raw-only output, warnings, errors |
| `-w -` stdout | binary pcap/pcapng only |

## Known scope boundaries

- Classic pcap rotation is supported; pcapng rotation is rejected explicitly.
- tcpdump options such as capture direction (`-Q`), timestamp-source and
  precision selection (`-j`, `-J`, `--time-stamp-precision`), link-type
  selection (`-y`, `-L`), filter dumping (`-d`), and post-rotation commands
  (`-z`) are not implemented yet.
- Application-layer printing covers DNS and HTTP; the remaining protocols are
  rendered generically. `-w` retains all raw bytes regardless.
- Rotated segments are named `capture_001.pcap` rather than tcpdump's
  `capture1`, including under `-W`.

These boundaries are deliberate and visible in validation/help; no unsupported
feature is silently treated as success.
