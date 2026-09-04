//go:generate go run ./cmd/gendocs docs/documentation.md

// tcpdump_go is a tcpdump-compatible packet analyzer with richer statistics
// and lossless classic-pcap/pcapng processing.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"tcpdump_go/capture"
	"tcpdump_go/display"
	"tcpdump_go/internal/pathguard"
)

const defaultSnaplen = uint64(262144)

type cliOptions struct {
	iface      string
	readPcap   string
	filter     string
	filterFile string
	count      uint64

	outPcap      string
	pcapngOutput bool
	rotateSize   uint64
	rotateTime   uint64
	rotateMB     uint64
	maxFiles     uint64
	rotateSecs   uint64
	csvOut       string
	printPackets bool

	snaplen         uint64
	bufferKB        uint64
	promisc         bool
	noPromisc       bool
	disableOffload  bool
	dropUser        string
	noImmediateMode bool

	verbosity    int
	hex          bool
	hexASCII     bool
	hexLink      bool
	hexASCIILink bool
	ascii        bool
	quick        bool
	linkHeader   bool
	absSeq       bool
	number       bool

	noTimestamp bool
	unixTime    bool
	deltaTime   bool
	dateTime    bool

	disableDNS     bool
	disableDNSAll  bool
	foreignNumeric bool
	showStats      bool
	statsOnly      bool
	countOnly      bool
	lineBuffered   bool
	packetBuffered bool
	listInterfaces bool
	version        bool
	color          string
}

// boolFlags lists flags eligible for POSIX-style combination (-nXX, -vv,
// -tttt). Long flags are intentionally excluded from expansion.
var boolFlags = []string{
	"disable-offload", "stats-only", "immediate-mode", "pcapng", "print",
	"stats", "version", "promisc", "tttt", "nn", "xx", "XX", "ttt",
	"tt", "A", "D", "N", "S", "U", "e", "f", "l", "n", "p", "q",
	"t", "v", "x", "X", "#",
}

// valueFlags lists single-letter flags taking a value. getopt allows the value
// to be glued on (-c100, -nni eth0), so those forms are accepted too. No name
// here collides with boolFlags, which keeps the split unambiguous.
var valueFlags = []string{"B", "C", "F", "G", "W", "Z", "c", "i", "r", "s", "w"}

// expandArgs rewrites combined POSIX arguments into the one-flag-per-argument
// form the flag package needs.
func expandArgs(args []string) []string {
	out := make([]string, 0, len(args)+4)
	for _, arg := range args {
		expanded, ok := expandArg(arg)
		if ok {
			out = append(out, expanded...)
			continue
		}
		out = append(out, arg)
	}
	return out
}

// expandArg expands one argument. Anything not fully recognized is left
// untouched so the flag package reports it verbatim.
func expandArg(arg string) ([]string, bool) {
	if len(arg) < 3 || arg[0] != '-' || arg[1] == '-' || strings.Contains(arg, "=") {
		return nil, false
	}
	rest := arg[1:]
	expanded := make([]string, 0, 4)
	for rest != "" {
		if name, ok := matchFlag(rest, boolFlags); ok {
			expanded = append(expanded, "-"+name)
			rest = rest[len(name):]
			continue
		}
		name, ok := matchFlag(rest, valueFlags)
		if !ok {
			return nil, false
		}
		// A value flag ends the cluster: the rest is its value, or the value is
		// the next argument when nothing is glued on.
		expanded = append(expanded, "-"+name)
		if value := rest[len(name):]; value != "" {
			expanded = append(expanded, value)
		}
		rest = ""
	}
	if len(expanded) < 2 {
		return nil, false
	}
	return expanded, true
}

// verbosityCounter is a flag.Value that counts occurrences instead of taking a
// value, so -v -vv -vvv all raise the level the way tcpdump does.
type verbosityCounter int

func (c *verbosityCounter) String() string   { return strconv.Itoa(int(*c)) }
func (c *verbosityCounter) IsBoolFlag() bool { return true }

func (c *verbosityCounter) Set(value string) error {
	// "-v=false" resets; a bare "-v" arrives as "true".
	if value == "false" {
		*c = 0
		return nil
	}
	*c++
	return nil
}

func matchFlag(rest string, names []string) (string, bool) {
	for _, name := range names {
		if strings.HasPrefix(rest, name) {
			return name, true
		}
	}
	return "", false
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "tcpdump_go: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) (retErr error) {
	options, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if options.version {
		_, err := fmt.Fprintln(stdout, versionString())
		return err
	}
	if err := finalizeOptions(&options); err != nil {
		return err
	}
	previousColor := display.UseColor
	defer func() { display.UseColor = previousColor }()

	// Only a genuinely empty invocation has the documented "list and exit"
	// shorthand. Options such as -w or --stats without a source are mistakes,
	// not requests to silently ignore those options.
	if options.listInterfaces || len(args) == 0 {
		if err := configureDisplay(stdout, options.lineBuffered, options.color); err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, display.ResetOutput()) }()
		return capture.PrintInterfaces(options.verbosity)
	}
	if options.iface == "" && options.readPcap == "" {
		return errors.New("a capture source is required: use -i <interface> or -r <file>")
	}

	printPackets := options.outPcap == "" || options.printPackets
	if options.statsOnly || options.countOnly {
		printPackets = false
	}
	textOutput := stdout
	if options.outPcap == "-" || (options.outPcap != "" && !printPackets) {
		textOutput = stderr
	}
	if err := configureDisplay(textOutput, options.lineBuffered, options.color); err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, display.FlushOut(), display.ResetOutput())
	}()
	display.ConfigureRenderer(display.RenderOptions{
		LinkHeader:              options.linkHeader,
		ShowPacketNumber:        options.number,
		AbsoluteSequenceNumbers: options.absSeq,
		NumericPorts:            options.disableDNS,
	})
	defer display.ResetRenderer()

	viewMode := selectViewMode(options)
	tsMode := selectTimestampMode(options)
	if options.readPcap != "" {
		return runReadPcap(options, viewMode, tsMode, printPackets, stdout, stderr)
	}
	return capture.RunCapture(capture.Config{
		Iface:                options.iface,
		Filter:               options.filter,
		OutPcap:              options.outPcap,
		PcapNG:               options.pcapngOutput,
		Snaplen:              uint32(options.snaplen),  //nolint:gosec // finalizeOptions rejects values above MaxInt32
		BufSize:              uint32(options.bufferKB), //nolint:gosec // finalizeOptions rejects values above MaxInt32/1024
		Promisc:              options.promisc,
		RotateSize:           options.rotateSize,
		RotateTime:           options.rotateTime,
		MaxFiles:             options.maxFiles,
		ViewMode:             viewMode,
		TSMode:               tsMode,
		Verbosity:            options.verbosity,
		DisableDNS:           options.disableDNS,
		ShowStats:            options.showStats,
		Quiet:                !printPackets,
		Count:                options.count,
		DisableOffload:       options.disableOffload,
		DropUser:             options.dropUser,
		NoImmediateMode:      options.noImmediateMode,
		FlushEveryPacket:     options.lineBuffered,
		FlushPcapEveryPacket: options.packetBuffered,
		StatusWriter:         stderr,
	})
}

func parseOptions(args []string, stderr io.Writer) (cliOptions, error) {
	var options cliOptions
	fs := flag.NewFlagSet("tcpdump_go", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&options.iface, "i", "", "capture interface: name, or the number shown by -D")
	fs.StringVar(&options.readPcap, "r", "", "read pcap/pcapng file; - means stdin")
	fs.StringVar(&options.filter, "filter", "", "BPF expression (extension; positional syntax is preferred)")
	fs.StringVar(&options.filterFile, "F", "", "read BPF expression from file")
	fs.Uint64Var(&options.count, "c", 0, "stop after N matching packets")

	fs.StringVar(&options.outPcap, "w", "", "write raw packets; - means stdout")
	fs.BoolVar(&options.pcapngOutput, "pcapng", false, "write pcapng rather than classic pcap")
	fs.Uint64Var(&options.maxFiles, "W", 0, "limit rotation to N files (cyclic with -C, stop with -G)")
	fs.Uint64Var(&options.rotateMB, "C", 0, "rotate after N million bytes")
	fs.Uint64Var(&options.rotateSecs, "G", 0, "rotate every N seconds")
	fs.Uint64Var(&options.rotateSize, "rotate-size", 0, "rotate after N bytes (extension)")
	fs.Uint64Var(&options.rotateTime, "rotate-time", 0, "rotate every N seconds (extension)")
	fs.StringVar(&options.csvOut, "csv", "", "write aggregated flows as CSV (offline)")
	fs.BoolVar(&options.printPackets, "print", false, "also print packet summaries with -w")

	fs.Uint64Var(&options.snaplen, "s", defaultSnaplen, "snapshot length; 0 selects the default maximum")
	fs.Uint64Var(&options.bufferKB, "B", 0, "capture buffer size in KiB")
	fs.BoolVar(&options.promisc, "promisc", true, "enable promiscuous mode (legacy extension)")
	fs.BoolVar(&options.noPromisc, "p", false, "do not capture in promiscuous mode")
	fs.BoolVar(&options.disableOffload, "disable-offload", false, "temporarily disable and later restore NIC offloads (Linux)")
	fs.StringVar(&options.dropUser, "Z", "", "drop privileges to this user after opening the capture source")
	immediateMode := true
	fs.BoolVar(&immediateMode, "immediate-mode", true, "deliver packets as they arrive; --immediate-mode=false buffers for throughput")

	fs.Var((*verbosityCounter)(&options.verbosity), "v", "verbose packet details; repeat for more (-vv, -vvv)")
	fs.BoolVar(&options.hex, "x", false, "hex dump without link header")
	fs.BoolVar(&options.hexASCII, "X", false, "hex and ASCII without link header")
	fs.BoolVar(&options.hexLink, "xx", false, "hex dump including link header")
	fs.BoolVar(&options.hexASCIILink, "XX", false, "hex and ASCII including link header")
	fs.BoolVar(&options.ascii, "A", false, "ASCII dump without link header")
	fs.BoolVar(&options.quick, "q", false, "quick/short protocol output")
	fs.BoolVar(&options.linkHeader, "e", false, "print link-layer header")
	fs.BoolVar(&options.absSeq, "S", false, "print absolute TCP sequence numbers")
	fs.BoolVar(&options.number, "#", false, "print packet number")
	fs.BoolVar(&options.number, "number", false, "print packet number")

	fs.BoolVar(&options.noTimestamp, "t", false, "do not print timestamps")
	fs.BoolVar(&options.unixTime, "tt", false, "print Unix timestamps")
	fs.BoolVar(&options.deltaTime, "ttt", false, "print delta from previous packet")
	fs.BoolVar(&options.dateTime, "tttt", false, "print local date and time")

	fs.BoolVar(&options.disableDNS, "n", false, "do not resolve host names")
	fs.BoolVar(&options.disableDNSAll, "nn", false, "do not resolve host or service names")
	fs.BoolVar(&options.foreignNumeric, "f", false, "print foreign addresses numerically")
	fs.BoolVar(&options.showStats, "stats", false, "print extended session statistics")
	fs.BoolVar(&options.statsOnly, "stats-only", false, "suppress packets and print statistics")
	fs.BoolVar(&options.countOnly, "count", false, "count matching packets without printing them")
	fs.BoolVar(&options.lineBuffered, "l", false, "flush text output after each packet")
	fs.BoolVar(&options.packetBuffered, "U", false, "flush raw capture output after each packet")
	fs.BoolVar(&options.listInterfaces, "D", false, "list capture interfaces")
	fs.BoolVar(&options.version, "version", false, "print version")
	fs.StringVar(&options.color, "color", "auto", "color mode: auto, always, never")

	fs.Usage = func() { printUsage(fs.Output()) }
	if err := fs.Parse(expandArgs(args)); err != nil {
		return cliOptions{}, err
	}
	options.noImmediateMode = !immediateMode
	positional := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if positional != "" && options.filter != "" {
		return cliOptions{}, errors.New("use either a positional BPF expression or --filter, not both")
	}
	if positional != "" {
		options.filter = positional
	}
	if options.filterFile != "" {
		if options.filter != "" {
			return cliOptions{}, errors.New("-F cannot be combined with another BPF expression")
		}
		filter, err := readFilterFile(options.filterFile)
		if err != nil {
			return cliOptions{}, err
		}
		options.filter = filter
	}
	return options, nil
}

func finalizeOptions(options *cliOptions) error {
	if options.iface != "" && options.readPcap != "" {
		return errors.New("-i and -r are mutually exclusive")
	}
	// tcpdump accepts the device number printed by -D as well as its name.
	resolved, err := capture.ResolveInterface(options.iface)
	if err != nil {
		return err
	}
	options.iface = resolved
	if options.snaplen == 0 {
		options.snaplen = defaultSnaplen
	}
	if options.snaplen > math.MaxInt32 {
		return fmt.Errorf("snaplen %d exceeds libpcap limit %d", options.snaplen, int64(math.MaxInt32))
	}
	if options.bufferKB > math.MaxInt32/1024 {
		return fmt.Errorf("capture buffer %d KiB exceeds libpcap limit", options.bufferKB)
	}
	if options.noPromisc {
		options.promisc = false
	}
	if options.dropUser != "" && options.disableOffload {
		return errors.New("-Z cannot be combined with --disable-offload: restoring NIC offloads requires the privileges being dropped")
	}
	// tcpdump's -n already suppresses both host and port name lookup, so -nn
	// and -f fold into the same switch. Verified against tcpdump: -n and -nn
	// print identical address.port pairs.
	options.disableDNS = options.disableDNS || options.disableDNSAll || options.foreignNumeric
	if options.statsOnly {
		options.showStats = true
	}
	if options.csvOut != "" && options.readPcap == "" {
		return errors.New("-csv requires offline input with -r")
	}
	if options.csvOut == "-" {
		return errors.New("-csv - is not supported because it can corrupt packet/statistics output")
	}
	if options.rotateMB > 0 {
		if options.rotateSize > 0 {
			return errors.New("use either -C or -rotate-size, not both")
		}
		if options.rotateMB > math.MaxUint64/1_000_000 {
			return errors.New("-C value is too large")
		}
		options.rotateSize = options.rotateMB * 1_000_000
	}
	if options.rotateSecs > 0 {
		if options.rotateTime > 0 {
			return errors.New("use either -G or -rotate-time, not both")
		}
		options.rotateTime = options.rotateSecs
	}
	if options.maxFiles > 0 && options.rotateSize == 0 && options.rotateTime == 0 {
		return errors.New("-W needs a rotation trigger: combine it with -C or -G")
	}
	if (options.rotateSize > 0 || options.rotateTime > 0) && options.outPcap == "" {
		return errors.New("capture rotation requires -w")
	}
	if options.outPcap != "" && strings.EqualFold(filepath.Ext(options.outPcap), ".pcapng") {
		options.pcapngOutput = true
	}
	if options.pcapngOutput && (options.rotateSize > 0 || options.rotateTime > 0) {
		return errors.New("pcapng rotation is not yet supported; choose classic .pcap or disable rotation")
	}
	if options.outPcap == "-" && (options.rotateSize > 0 || options.rotateTime > 0) {
		return errors.New("rotation is not supported for -w -")
	}
	if options.packetBuffered && options.outPcap == "" {
		return errors.New("-U requires raw output with -w")
	}
	if options.pcapngOutput && options.outPcap == "" {
		return errors.New("--pcapng requires raw output with -w")
	}
	if options.printPackets && options.outPcap == "" {
		return errors.New("--print requires raw output with -w")
	}
	switch options.color {
	case "auto", "always", "never":
	default:
		return fmt.Errorf("invalid --color value %q (want auto, always, or never)", options.color)
	}
	if options.readPcap != "" {
		if err := pathguard.ValidateOutputPaths(options.readPcap, options.outPcap, options.csvOut, options.rotateSize > 0 || options.rotateTime > 0); err != nil {
			return err
		}
	}
	return nil
}

func selectViewMode(options cliOptions) display.ViewMode {
	switch {
	case options.hexASCIILink:
		return display.ViewHexASCIILink
	case options.hexLink:
		return display.ViewHexLink
	case options.hexASCII:
		return display.ViewHexASCII
	case options.hex:
		return display.ViewHex
	case options.ascii:
		return display.ViewASCII
	case options.quick:
		return display.ViewQuick
	case options.verbosity > 0:
		return display.ViewVerbose
	default:
		return display.ViewNormal
	}
}

func selectTimestampMode(options cliOptions) display.TSMode {
	switch {
	case options.dateTime:
		return display.TSDateTime
	case options.deltaTime:
		return display.TSDelta
	case options.unixTime:
		return display.TSUnix
	case options.noTimestamp:
		return display.TSNone
	default:
		return display.TSDefault
	}
}

func configureDisplay(output io.Writer, lineBuffered bool, color string) error {
	bufferSize := 256 * 1024
	if lineBuffered {
		bufferSize = 0
	}
	if err := display.SetOutput(output, bufferSize); err != nil {
		return fmt.Errorf("configure output: %w", err)
	}
	switch color {
	case "always":
		display.UseColor = true
	case "never":
		display.UseColor = false
	default:
		display.UseColor = isTerminal(output)
	}
	return nil
}

func isTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func readFilterFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is supplied explicitly by the user
	if err != nil {
		return "", fmt.Errorf("read BPF filter file %q: %w", path, err)
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	filter := strings.Join(lines, " ")
	if filter == "" {
		return "", fmt.Errorf("BPF filter file %q is empty", path)
	}
	return filter, nil
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprint(writer, `Usage: tcpdump_go [options] [BPF expression]

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
  -n/-nn             disable name resolution
  -f                 print foreign addresses numerically
  -l                 flush text output after every packet

Capture and extensions:
  -s N               snapshot length (default 262144)
  -B N               kernel buffer in KiB
  -p                 disable promiscuous mode
  -Z user            drop privileges to user once the source is open
  --immediate-mode   deliver packets as they arrive (default; =false buffers)
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
`)
}

func versionString() string {
	version := "devel"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	return "tcpdump_go " + version + " (Go " + strings.TrimPrefix(runtimeVersion(), "go") + ")"
}

var runtimeVersion = runtime.Version
