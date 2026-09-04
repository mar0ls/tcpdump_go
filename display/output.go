// Package display provides packet formatting and output utilities:
// ANSI colors, buffered output, a bounded DNS cache, hex dumps, and packet
// header formatting.
package display

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultOutputBufferSize = 256 * 1024
	dnsCacheCapacity        = 1024
	dnsLookupTimeout        = 250 * time.Millisecond
	dnsPositiveTTL          = 10 * time.Minute
	dnsNegativeTTL          = 30 * time.Second
	dnsPendingTTL           = 5 * time.Second
	dnsQueueCapacity        = 256
	dnsWorkerCount          = 4
)

// UseColor controls whether output includes ANSI escape codes.
var UseColor bool

func init() {
	fi, err := os.Stdout.Stat()
	UseColor = err == nil && (fi.Mode()&os.ModeCharDevice != 0)
}

// dnsWorkersOnce keeps the resolver pool lazy: -n, -w and --version never look
// up a name, and those runs should not start background goroutines at all.
var dnsWorkersOnce sync.Once

func startDNSWorkers() {
	dnsWorkersOnce.Do(func() {
		for range dnsWorkerCount {
			go dnsWorker()
		}
	})
}

// ANSI escape codes for terminal colorization.
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
)

// SetOutput directs subsequent display output to w.  A positive bufferSize
// enables normal buffering.  A bufferSize <= 0 flushes after every display
// write, which is useful for line-oriented terminal or stderr output.
//
// SetOutput flushes the previous writer first and returns that flush error.
// Configuration is intended to happen before packet rendering starts.
func SetOutput(w io.Writer, bufferSize int) error {
	return defaultPrinter.SetOutput(w, bufferSize)
}

// ResetOutput restores buffered stdout output.
func ResetOutput() error {
	return SetOutput(os.Stdout, defaultOutputBufferSize)
}

// FlushOut flushes the buffered output writer.  Returning the error lets the
// caller distinguish successful capture from partial output (for example, on
// a full disk or a closed pipe).
func FlushOut() error {
	return defaultPrinter.Flush()
}

func writeOutput(p []byte) error {
	return defaultPrinter.Write(p)
}

// Outf writes a formatted string to Out and reports an immediate or
// line-buffer flush error.  A final FlushOut still needs to be checked when
// normal buffering is enabled.
func Outf(format string, args ...any) error {
	return defaultPrinter.Outf(format, args...)
}

// Outln writes args followed by a newline to Out.
func Outln(args ...any) error {
	return defaultPrinter.Outln(args...)
}

// Colorize wraps s in the given ANSI color code; no-op when UseColor is false.
func Colorize(s, color string) string {
	if !UseColor {
		return s
	}
	return color + s + ColorReset
}

type reverseResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
}

type dnsCacheEntry struct {
	ip      string
	name    string
	expires time.Time
	pending bool
}

var dnsState = struct {
	sync.Mutex
	entries  map[string]*list.Element
	lru      list.List
	resolver reverseResolver
	jobs     chan string
}{
	entries:  make(map[string]*list.Element, dnsCacheCapacity),
	resolver: net.DefaultResolver,
	jobs:     make(chan string, dnsQueueCapacity),
}

// ResolveIP schedules a time-bounded reverse DNS lookup and immediately returns
// a cached name or the numeric address. Resolution is deliberately off the
// capture/render path, so a slow resolver cannot cause kernel packet drops.
func ResolveIP(ip string) string {
	return ResolveIPContext(context.Background(), ip)
}

// ResolveIPContext avoids scheduling new work when ctx is already cancelled.
// Lookups themselves use the package timeout because they continue in a
// bounded worker after this non-blocking function returns.
func ResolveIPContext(ctx context.Context, ip string) string {
	if net.ParseIP(ip) == nil {
		return ip
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return ip
	}
	startDNSWorkers()
	now := time.Now()
	dnsState.Lock()
	if elem, ok := dnsState.entries[ip]; ok {
		entry := elem.Value.(*dnsCacheEntry)
		if now.Before(entry.expires) {
			dnsState.lru.MoveToFront(elem)
			name := entry.name
			dnsState.Unlock()
			return name
		}
		dnsState.lru.Remove(elem)
		delete(dnsState.entries, ip)
	}
	entry := &dnsCacheEntry{ip: ip, name: ip, expires: now.Add(dnsPendingTTL), pending: true}
	dnsState.entries[ip] = dnsState.lru.PushFront(entry)
	for len(dnsState.entries) > dnsCacheCapacity {
		oldest := dnsState.lru.Back()
		if oldest == nil {
			break
		}
		delete(dnsState.entries, oldest.Value.(*dnsCacheEntry).ip)
		dnsState.lru.Remove(oldest)
	}
	jobs := dnsState.jobs
	dnsState.Unlock()

	select {
	case jobs <- ip:
	default:
		// A saturated DNS queue must never apply backpressure to packet output.
		dnsState.Lock()
		if elem, ok := dnsState.entries[ip]; ok {
			queued := elem.Value.(*dnsCacheEntry)
			queued.pending = false
			queued.expires = time.Now().Add(dnsNegativeTTL)
		}
		dnsState.Unlock()
	}
	return ip
}

func dnsWorker() {
	for ip := range dnsState.jobs {
		dnsState.Lock()
		resolver := dnsState.resolver
		dnsState.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		names, err := resolver.LookupAddr(ctx, ip)
		cancel()

		name := ip
		ttl := dnsNegativeTTL
		if err == nil && len(names) > 0 {
			if resolved := strings.TrimSuffix(names[0], "."); resolved != "" {
				name = resolved
				ttl = dnsPositiveTTL
			}
		}

		dnsState.Lock()
		if elem, ok := dnsState.entries[ip]; ok {
			entry := elem.Value.(*dnsCacheEntry)
			if entry.pending {
				entry.name = name
				entry.pending = false
				entry.expires = time.Now().Add(ttl)
				dnsState.lru.MoveToFront(elem)
			}
		}
		dnsState.Unlock()
	}
}

// ClearDNSCache removes ip from the reverse-DNS cache.  Passing an empty
// string clears the complete cache, which is useful between capture sessions.
func ClearDNSCache(ip string) {
	dnsState.Lock()
	defer dnsState.Unlock()
	if ip == "" {
		clear(dnsState.entries)
		dnsState.lru.Init()
		return
	}
	if elem, ok := dnsState.entries[ip]; ok {
		dnsState.lru.Remove(elem)
		delete(dnsState.entries, ip)
	}
}

// CaptureOut redirects Out to an in-memory buffer; returns the buffer and a
// restore function.  It is intended for tests and should not race with live
// packet rendering.
func CaptureOut() (*bytes.Buffer, func()) {
	return defaultPrinter.Capture()
}
