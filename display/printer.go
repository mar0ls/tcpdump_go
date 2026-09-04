package display

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Printer owns one output stream and the render state of a single capture
// session: presentation options and per-flow TCP sequence bases. The
// package-level functions delegate to defaultPrinter.
//
// Colour is deliberately not here: it describes the terminal, not a session.
type Printer struct {
	mu              sync.Mutex
	out             *bufio.Writer
	flushEveryWrite bool

	options RenderOptions
	seqBase map[tcpConversation]tcpSequenceBase
}

// defaultRenderOptions keeps the historical library defaults for callers that
// never configure a session. The CLI selects tcpdump's defaults explicitly.
func defaultRenderOptions() RenderOptions {
	return RenderOptions{ShowPacketNumber: true, NumericPorts: true}
}

// NewPrinter returns a Printer writing to w. A bufferSize of zero or less
// flushes after every write, which is what line-oriented output needs.
func NewPrinter(w io.Writer, bufferSize int) *Printer {
	flushEvery := bufferSize <= 0
	if bufferSize <= 0 {
		bufferSize = 1
	}
	return &Printer{
		out:             bufio.NewWriterSize(w, bufferSize),
		flushEveryWrite: flushEvery,
		options:         defaultRenderOptions(),
		seqBase:         make(map[tcpConversation]tcpSequenceBase),
	}
}

var defaultPrinter = NewPrinter(os.Stdout, defaultOutputBufferSize)

// SetOutput redirects the printer, flushing the previous writer and returning
// that flush error.
func (p *Printer) SetOutput(w io.Writer, bufferSize int) error {
	if w == nil {
		return errors.New("display: nil output writer")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.out.Flush()
	p.flushEveryWrite = bufferSize <= 0
	if bufferSize <= 0 {
		bufferSize = 1
	}
	p.out = bufio.NewWriterSize(w, bufferSize)
	return err
}

// Flush empties the buffer. The error distinguishes a complete capture from
// partial output on a full disk or closed pipe.
func (p *Printer) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.Flush()
}

// Write emits raw bytes, honouring the flush-every-write setting.
func (p *Printer) Write(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.out.Write(b); err != nil {
		return err
	}
	return p.flushLocked()
}

// Outf writes a formatted line.
func (p *Printer) Outf(format string, args ...any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := fmt.Fprintf(p.out, format, args...); err != nil {
		return err
	}
	return p.flushLocked()
}

// Outln writes args followed by a newline.
func (p *Printer) Outln(args ...any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := fmt.Fprintln(p.out, args...); err != nil {
		return err
	}
	return p.flushLocked()
}

func (p *Printer) flushLocked() error {
	if p.flushEveryWrite {
		return p.out.Flush()
	}
	return nil
}

// Configure applies options and drops relative TCP sequence state, which
// belongs to the previous session.
func (p *Printer) Configure(options RenderOptions) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.options = options
	clear(p.seqBase)
}

// Reset restores the package defaults and clears per-flow state.
func (p *Printer) Reset() {
	p.Configure(defaultRenderOptions())
}

func (p *Printer) renderOptions() RenderOptions {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.options
}

// Capture redirects the printer into a buffer and returns a restore function.
// Holding a Printer means a test can read its own output instead of swapping
// process-wide state.
func (p *Printer) Capture() (*bytes.Buffer, func()) {
	buf := &bytes.Buffer{}
	p.mu.Lock()
	_ = p.out.Flush()
	previous, previousFlush := p.out, p.flushEveryWrite
	p.out, p.flushEveryWrite = bufio.NewWriter(buf), false
	p.mu.Unlock()

	return buf, func() {
		p.mu.Lock()
		_ = p.out.Flush()
		p.out, p.flushEveryWrite = previous, previousFlush
		p.mu.Unlock()
	}
}
