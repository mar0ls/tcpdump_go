// Package display provides packet formatting and output utilities:
// ANSI colors, buffered stdout, DNS cache, hex dumps, and header formatting.
package display

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

// Out is the buffered stdout writer (256 KB). Batches small writes into a single syscall.
var Out = bufio.NewWriterSize(os.Stdout, 256*1024)

// UseColor controls whether output includes ANSI escape codes.
var UseColor bool

func init() {
	fi, err := os.Stdout.Stat()
	UseColor = err == nil && (fi.Mode()&os.ModeCharDevice != 0)
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

// FlushOut flushes the buffered stdout writer. Call after writing a logical
// batch of output to avoid stale data in the buffer.
func FlushOut() {
	if err := Out.Flush(); err != nil {
		log.Printf("flush stdout: %v", err)
	}
}

// Outf writes a formatted string to the buffered stdout writer.
func Outf(format string, args ...any) {
	_, _ = fmt.Fprintf(Out, format, args...)
}

// Outln writes args followed by a newline to the buffered stdout writer.
func Outln(args ...any) {
	_, _ = fmt.Fprintln(Out, args...)
}

// Colorize wraps s in the given ANSI color code. Returns s unchanged when
// UseColor is false (e.g. stdout is not a terminal).
func Colorize(s, color string) string {
	if !UseColor {
		return s
	}
	return color + s + ColorReset
}

var dnsCache sync.Map

// ResolveIP performs a reverse DNS lookup for ip and caches the result.
// Returns the original IP string on failure or when no PTR record exists.
func ResolveIP(ip string) string {
	if v, ok := dnsCache.Load(ip); ok {
		return v.(string)
	}
	result := ip
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		result = strings.TrimSuffix(names[0], ".")
	}
	dnsCache.Store(ip, result)
	return result
}

// ClearDNSCache removes ip from the reverse-DNS cache.
func ClearDNSCache(ip string) {
	dnsCache.Delete(ip)
}

// CaptureOut redirects Out to an in-memory buffer and returns the buffer and
// a restore function. Used in tests to capture printed output.
func CaptureOut() (*bytes.Buffer, func()) {
	buf := &bytes.Buffer{}
	old := Out
	Out = bufio.NewWriter(buf)
	return buf, func() { Out = old }
}
