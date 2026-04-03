# tcpdump_go

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![docs](https://img.shields.io/badge/docs-generated-blue)
[![Release](https://img.shields.io/github/v/release/mar0ls/tcpdump_go)](https://github.com/mar0ls/tcpdump_go/releases/latest)

Network packet analyzer written in Go, built on [gopacket](https://github.com/google/gopacket) and libpcap.
Compatible with tcpdump's flag set, plus extras: pcap file rotation, flow CSV export, colorized output, and detailed statistics.

## Requirements

- Go 1.21+
- libpcap (`sudo apt install libpcap-dev` / `brew install libpcap`)
- Root or `CAP_NET_RAW` for live capture
- **Windows:** [Npcap](https://npcap.com/) instead of libpcap

## Installation

```bash
git clone https://github.com/mar0ls/tcpdump_go.git
cd tcpdump_go
go build -o tcpdump_go .
```

## Usage

```text
sudo ./tcpdump_go [options] [BPF expression]
```

Running without `-i` lists available interfaces.

## Flags

Single-letter flags can be combined POSIX-style: `-nXX`, `-nvXX`, `-ntttt`, etc.

```text
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
  -v              Verbose: tos/ttl/id/offset/flags/proto + seq/ack/win for TCP
  -x              Hex without Ethernet header
  -X              Hex + ASCII without Ethernet header
  -xx             Hex with Ethernet header
  -XX             Hex + ASCII with Ethernet header

Timestamp (compatible with tcpdump):
  -t              No timestamp
  -tt             Unix timestamp (seconds.microseconds)
  -ttt            Delta from previous packet
  -tttt           Date + time (2006-01-02 15:04:05.000000)

Misc:
  -n              Disable reverse DNS
  -q              Quiet mode — no packet output (use with -stats)
  -stats          Print statistics summary on exit
```

## Examples

```bash
# List available interfaces
sudo ./tcpdump_go

# Capture HTTP traffic on eth0
sudo ./tcpdump_go -i eth0 -f "tcp port 80"

# First 100 packets, no DNS, verbose — POSIX-style flags
sudo ./tcpdump_go -i eth0 -c 100 -nv

# Hex+ASCII with Ethernet header, no DNS
sudo ./tcpdump_go -i eth0 -nXX

# Date + time (like tcpdump -tttt)
sudo ./tcpdump_go -i eth0 -ntttt

# Inter-packet time delta
sudo ./tcpdump_go -i eth0 -nttt

# Write to pcap with BPF filter
sudo ./tcpdump_go -i eth0 -f "not port 22" -w capture.pcap

# Rotate every 100 MB
sudo ./tcpdump_go -i eth0 -w capture.pcap -rotate-size 104857600

# Rotate every 60 seconds
sudo ./tcpdump_go -i eth0 -w capture.pcap -rotate-time 60

# Large kernel buffer (64 MB) for bursty traffic
sudo ./tcpdump_go -i eth0 -B 65536

# Statistics only, no packet output
sudo ./tcpdump_go -i eth0 -q -stats

# Read pcap file with hex+ASCII view
./tcpdump_go -r capture.pcap -nX

# Export flows to CSV
./tcpdump_go -r capture.pcap -csv flows.csv

# Disable NIC offloading before capture (Linux, root)
sudo ./tcpdump_go -i eth0 -disable-offload
```

## Performance vs tcpdump

Test file: **15 MB pcap, 17 361 packets**. Platform: macOS arm64 (Apple Silicon M-series).
Measured with: `time ./binary -r file > /dev/null`.

| Mode | tcpdump | tcpdump_go | Difference |
| ---- | ------- | ---------- | ---------- |
| Normal (`-n`) | 0.040s | **0.038s** | comparable |
| Verbose (`-nv`) | 0.035s | **0.032s** | comparable |
| Hex (`-nx`) | 0.497s | **0.042s** | **11.8× faster** |
| Hex+ASCII (`-nX`) | 0.462s | **0.104s** | **4.4× faster** |
| Hex+ASCII with L2 (`-nXX`) | 0.467s | **0.105s** | **4.4× faster** |

### Why hex is faster

tcpdump uses `fprintf("%02x", byte)` — one syscall per byte. tcpdump_go uses:

- **lookup table** `hexTable` — nibble→hex without format calls
- **`sync.Pool`** of pre-allocated buffers — zero allocations per row
- **`bufio.Writer` 256 KB** — one stdout syscall per ~200 rows
- **worker goroutine** — write + print in parallel with capture

### GOGC=off for file processing

For modes that generate many allocations (gopacket allocates per-packet objects), GC can be disabled:

```bash
GOGC=off ./tcpdump_go -r capture.pcap -n
```

`GOGC=off` is a **runtime environment variable**, not a compiler flag. It has no effect on the binary itself.
Effect on 15 MB pcap: normal 0.038s → **0.027s** (~30% faster).
Note: with live capture it causes unbounded memory growth — only use with `-r`.

## How operating system kernels process packets

### Linux

```text
NIC → DMA ring buffer (kernel) → BPF filter (kernel) → libpcap ring (mmap) → userspace
```

1. **NIC DMA ring buffer** — the NIC writes packets directly to kernel memory via DMA, with no CPU involvement.
2. **BPF filter in kernel** — the filter (`-f "tcp port 443"`) is JIT-compiled and evaluated *before* the packet leaves the kernel. Non-matching packets are never copied to userspace.
3. **TPACKET_V3 ring buffer** — libpcap automatically negotiates a shared memory mapping (`mmap`) with the kernel. Packets go directly into the shared buffer — **zero-copy** kernel→userspace. `NoCopy=true` in gopacket avoids a further copy.
4. **Tuning**:
   - `sysctl -w net.core.rmem_max=536870912` — max buffer 512 MB
   - `-B 65536` (64 MB) — libpcap buffer size
   - `-disable-offload` — disables TSO/GRO that merge/split packets before BPF

### macOS

```text
NIC → IOKit driver → BPF device (/dev/bpf0) → userspace read()
```

1. **BPF device** — Berkeley Packet Filter, the original BSD implementation. Accessed via `/dev/bpfN`.
2. **BPF batching** — by default `read()` returns *multiple* packets at once (when the buffer is full or on timeout). `ImmediateMode=true` disables the timeout and delivers packets immediately — lower latency at the cost of batching.
3. **`BIOCSBLEN`** (SetBufferSize) — sets the BPF buffer size. Default ~32 KB; we set **2 MB** by default.
4. **Before offloading** — macOS BPF captures packets *before* hardware offload, so `-disable-offload` is not needed.
5. **Tuning**: `kern.ipc.maxsockbuf` via `/etc/sysctl.conf`

### Windows (Npcap)

```text
NIC → NDIS miniport driver → Npcap kernel driver → WinPcap API → userspace
```

1. **NDIS filter driver** — Npcap installs as an NDIS Lightweight Filter (LWF) driver, intercepting packets at the network driver level.
2. **Kernel-mode buffer** — Npcap buffers packets in kernel memory and delivers them to userspace via DeviceIoControl/ReadFile.
3. **No TPACKET_V3** — Windows has no mmap ring buffer equivalent; every `ReadFile` copies data kernel→userspace.
4. **Tuning**: buffer size via Npcap installer or `SetBufferSize` (API through libpcap).

## Feature comparison with tcpdump

| Feature | tcpdump | tcpdump_go |
| ------- | ------- | ---------- |
| Live capture | ✓ | ✓ |
| BPF filter | ✓ | ✓ |
| Read pcap/pcapng (`-r`) | ✓ | ✓ |
| Write pcap (`-w`) | ✓ | ✓ |
| Promiscuous mode | ✓ | ✓ |
| Kernel buffer (`-B`) | ✓ | ✓ |
| Immediate mode | ✓ | ✓ |
| Packet limit (`-c`) | ✓ | ✓ |
| Hex dump (`-x/-X/-xx/-XX`) | ✓ | ✓ |
| Verbose IP/TCP/UDP (`-v`) | ✓ | ✓ |
| Timestamp flags (`-t/-tt/-ttt/-tttt`) | ✓ | ✓ |
| POSIX-style combined flags (`-nXX`) | ✓ | ✓ |
| ARP decode | ✓ | ✓ |
| Packet number in output | ✗ | ✓ |
| pcap file rotation (`-rotate-size/time`) | ✗ | ✓ |
| tshark-style statistics (`-stats`) | ✗ | ✓ |
| Flow CSV export (`-csv`) | ✗ | ✓ |
| Colorized output | ✗ | ✓ |
| Reverse DNS with cache | ✗ | ✓ (no repeated lookups) |
| Disable NIC offloading | ✗ | ✓ (Linux, `-disable-offload`) |
| Hex dump 4–12× faster | ✗ | ✓ (lookup table + sync.Pool) |
| 1 MB pcap writer buffer | ✗ | ✓ (~30 syscalls/s instead of 16 000) |

## Statistics (`-stats`)

```text
── Session summary ──────────────────────────
  Duration         : 2m15.3s
  Packets total    : 129030  (954 pkt/s)
  Bytes total      : 66637452  (3940.8 kbps)
  Packet size      : min=42  avg=516  max=1514 B

── Protocol hierarchy ────────────────────────
  Protocol      Packets   Share
  TCP              84201   65.3%
  UDP              44411   34.4%
  ICMP               418    0.3%

── TCP flags ────────────────────────────────
  SYN: 1203  FIN: 987  RST: 42

── Top 5 senders ────────────────────────────
  192.168.1.100        45231
  ...
```

## CSV export (`-csv`)

Available only with `-r`. Produces aggregated flows in a NetFlow-like format:

```csv
src_ip,dst_ip,src_port,dst_port,proto,count
192.168.1.5,8.8.8.8,54321,53,UDP,42
192.168.1.5,93.184.216.34,54400,443,TCP,158
```

Useful for analysis in Python, Excel, or SIEM tools.

## Dropped packets

Zero kernel drops with proper buffer configuration.
Shown in statistics (`-stats`) as `Dropped (pcap)`.

### Capture architecture (2 goroutines)

```text
libpcap → [capture goroutine] → captureCh (buffered) → [worker goroutine] → print/pcap/stats
```

The capture goroutine does **one thing only**: enqueue the packet to the channel. No I/O.
The worker processes at its own pace. On Ctrl+C/SIGTERM: graceful drain — no packet in the channel is lost.

### Reducing drops

```bash
# Large kernel buffer (64 MB)
sudo ./tcpdump_go -i eth0 -B 65536

# Increase system limit (Linux)
sudo sysctl -w net.core.rmem_max=536870912

# Smaller snaplen = less data per packet
sudo ./tcpdump_go -i eth0 -s 96

# BPF filter — kernel discards unwanted packets before copying
sudo ./tcpdump_go -i eth0 -f "tcp port 443"

# Disable reverse DNS
sudo ./tcpdump_go -i eth0 -n
```

### Kernel limits

| OS | Default pcap buffer | tcpdump_go default | How to increase |
| -- | ------------------- | ------------------ | --------------- |
| Linux | ~208 KB | 2 MB | `sysctl -w net.core.rmem_max=536870912` |
| macOS | ~32 KB (BPF) | 2 MB | `kern.ipc.maxsockbuf=268435456` in `/etc/sysctl.conf` |
| Windows | ~1 MB (Npcap) | 2 MB | Npcap installer → buffer size |

## NIC offloading (`-disable-offload`, Linux only)

Modern NICs offload some CPU work to hardware. During capture this can produce "modified" packets.

| ethtool option | Effect without disabling |
| -------------- | ------------------------ |
| `tso` (TX Segmentation Offload) | TCP segments up to 64 KB instead of ~1500 B |
| `gro` (Generic Receive Offload) | multiple small packets merged into one |
| `rxvlan` | VLAN tags not visible in pcap |
| `rx/tx` checksum offload | incorrect checksums in pcap |

```bash
sudo ./tcpdump_go -i eth0 -disable-offload   # disable + start capture
```

Effect is temporary — resets on reboot. macOS captures before offloading — flag not needed.

## Output

| Stream | Content             | Buffering              |
| ------ | ------------------- | ---------------------- |
| stdout | packets, statistics | 256 KB `bufio.Writer`  |
| stderr | warnings, errors    | unbuffered             |

```bash
sudo ./tcpdump_go -i eth0 2>/dev/null          # packets only
sudo ./tcpdump_go -i eth0 > packets.txt        # packets to file
sudo ./tcpdump_go -i eth0 > pkts.txt 2> err.log
```
