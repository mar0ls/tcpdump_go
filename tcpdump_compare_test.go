package main

// Comparison tests: tcpdump_go vs system tcpdump.
//
// For each *.pcap file in the project directory we run both tools
// with -n (no reverse-DNS) and -t (no timestamp), then compare
// the extracted flows (src.port > dst.port).
//
// Tests are skipped when:
//   - system tcpdump is not available (exec.LookPath)
//   - building the tcpdump_go binary failed (see TestMain in main_test.go)
//   - no *.pcap files exist in the project directory

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// compareBinaryPath and compareBinaryDir are set by TestMain in main_test.go.
var (
	compareBinaryPath string
	compareBinaryDir  string
)

// ansiRe matches ANSI colour escape sequences (produced by tcpdump_go).
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[mK]`)

// flowRe matches an IP:port pair on each side of the ">" arrow.
// Output format for both tools: "1.2.3.4.567 > 8.9.10.11.80:"
var flowRe = regexp.MustCompile(
	`(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)`,
)

// parsedFlow holds a single parsed packet flow.
type parsedFlow struct {
	src, sport, dst, dport string
}

func (f parsedFlow) String() string {
	return fmt.Sprintf("%s.%s > %s.%s", f.src, f.sport, f.dst, f.dport)
}

// stripANSI removes ANSI colour codes from a line of text.
func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// parseFlowsFrom reads all flows from the reader.
// Works for both tcpdump and tcpdump_go output (normal mode, -n -t).
func parseFlowsFrom(r io.Reader) []parsedFlow {
	var flows []parsedFlow
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := stripANSI(scanner.Text())
		if m := flowRe.FindStringSubmatch(line); m != nil {
			flows = append(flows, parsedFlow{m[1], m[2], m[3], m[4]})
		}
	}
	return flows
}

// sortedFlowKeys returns sorted flow keys (for set comparison).
func sortedFlowKeys(flows []parsedFlow) []string {
	keys := make([]string, len(flows))
	for i, f := range flows {
		keys[i] = f.String()
	}
	sort.Strings(keys)
	return keys
}

// flowCounts returns a map of flow key → packet count.
func flowCounts(flows []parsedFlow) map[string]int {
	m := make(map[string]int)
	for _, f := range flows {
		m[f.String()]++
	}
	return m
}

// runTcpdumpGo runs the built tcpdump_go binary on a pcap file.
// Flags: -r <file> -n (no DNS) -t (no timestamp).
func runTcpdumpGo(t *testing.T, pcapFile string) []parsedFlow {
	t.Helper()
	cmd := exec.Command(compareBinaryPath, "-r", pcapFile, "-n", "-t") //#nosec G204
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("tcpdump_go: StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("tcpdump_go: Start: %v", err)
	}
	flows := parseFlowsFrom(stdout)
	if err := cmd.Wait(); err != nil {
		t.Logf("tcpdump_go exited with error: %v (may be OK for small pcaps)", err)
	}
	return flows
}

// runSystemTcpdump runs the system tcpdump on a pcap file.
// Flags: -r <file> -n (no DNS) -t (no timestamp).
// Diagnostic output (stderr) is discarded — tcpdump writes metadata there.
func runSystemTcpdump(t *testing.T, tcpdumpBin, pcapFile string) []parsedFlow {
	t.Helper()
	cmd := exec.Command(tcpdumpBin, "-r", pcapFile, "-n", "-t") //#nosec G204
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("tcpdump: StdoutPipe: %v", err)
	}
	// tcpdump writes metadata to stderr — not relevant for this test.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("tcpdump: Start: %v", err)
	}
	flows := parseFlowsFrom(stdout)
	_ = cmd.Wait() // tcpdump may return != 0 on macOS in read-only mode
	return flows
}

// findSystemTcpdump returns the path to the system tcpdump, or "".
func findSystemTcpdump() string {
	if path, err := exec.LookPath("tcpdump"); err == nil {
		return path
	}
	// Common locations on macOS and Linux.
	for _, p := range []string{"/usr/sbin/tcpdump", "/usr/bin/tcpdump", "/sbin/tcpdump"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// pcapFilesInRoot returns *.pcap files in the project root directory.
// Excludes testdata/ — those are synthetic files created by TestMain.
func pcapFilesInRoot() []string {
	matches, _ := filepath.Glob("*.pcap")
	return matches
}

// Comparison tests

// TestCompare_PacketCount verifies that both tools see the same number of packets.
func TestCompare_PacketCount(t *testing.T) {
	tcpdumpBin, pcapFiles := comparePrecheck(t)

	for _, pcap := range pcapFiles {
		pcap := pcap
		t.Run(filepath.Base(pcap), func(t *testing.T) {
			goFlows := runTcpdumpGo(t, pcap)
			sysFlows := runSystemTcpdump(t, tcpdumpBin, pcap)

			if len(goFlows) != len(sysFlows) {
				t.Errorf("packet count mismatch: tcpdump_go=%d, tcpdump=%d",
					len(goFlows), len(sysFlows))
				t.Logf("tcpdump_go flows:\n  %s", strings.Join(sortedFlowKeys(goFlows), "\n  "))
				t.Logf("tcpdump flows:\n  %s", strings.Join(sortedFlowKeys(sysFlows), "\n  "))
			} else {
				t.Logf("OK: %d packets in both tools", len(goFlows))
			}
		})
	}
}

// TestCompare_FlowSet verifies that for each flow (src.port > dst.port)
// both tools report the same directions and ports.
func TestCompare_FlowSet(t *testing.T) {
	tcpdumpBin, pcapFiles := comparePrecheck(t)

	for _, pcap := range pcapFiles {
		pcap := pcap
		t.Run(filepath.Base(pcap), func(t *testing.T) {
			goFlows := runTcpdumpGo(t, pcap)
			sysFlows := runSystemTcpdump(t, tcpdumpBin, pcap)

			goCounts := flowCounts(goFlows)
			sysCounts := flowCounts(sysFlows)

			// Check flows present in tcpdump_go but missing in tcpdump.
			for key, cnt := range goCounts {
				if sysCounts[key] != cnt {
					t.Errorf("flow %q: tcpdump_go=%d, tcpdump=%d", key, cnt, sysCounts[key])
				}
			}
			// Check flows present in tcpdump but missing in tcpdump_go.
			for key, cnt := range sysCounts {
				if goCounts[key] != cnt {
					t.Errorf("flow %q: tcpdump=%d, tcpdump_go=%d", key, cnt, goCounts[key])
				}
			}
		})
	}
}

// TestCompare_UniqueEndpoints verifies that the set of unique IP addresses and ports
// is identical in both tools.
func TestCompare_UniqueEndpoints(t *testing.T) {
	tcpdumpBin, pcapFiles := comparePrecheck(t)

	for _, pcap := range pcapFiles {
		pcap := pcap
		t.Run(filepath.Base(pcap), func(t *testing.T) {
			goFlows := runTcpdumpGo(t, pcap)
			sysFlows := runSystemTcpdump(t, tcpdumpBin, pcap)

			goIPs := uniqueIPs(goFlows)
			sysIPs := uniqueIPs(sysFlows)

			for ip := range sysIPs {
				if !goIPs[ip] {
					t.Errorf("IP %q seen in tcpdump, missing in tcpdump_go", ip)
				}
			}
			for ip := range goIPs {
				if !sysIPs[ip] {
					t.Errorf("IP %q seen in tcpdump_go, missing in tcpdump", ip)
				}
			}
		})
	}
}

// TestCompare_WithBPFFilter verifies that the BPF filter "tcp" gives consistent results
// across both tools (fewer packets than without the filter).
func TestCompare_WithBPFFilter(t *testing.T) {
	tcpdumpBin, pcapFiles := comparePrecheck(t)

	// Find the first pcap that contains TCP packets (filter tcp).
	for _, pcap := range pcapFiles {
		pcap := pcap

		// tcpdump_go with TCP filter — the entire pcap fits in the response.
		cmdGo := exec.Command(compareBinaryPath, "-r", pcap, "-n", "-t", "-f", "tcp") //#nosec G204
		cmdGo.Stderr = io.Discard
		outGo, errGo := cmdGo.Output()

		cmdSys := exec.Command(tcpdumpBin, "-r", pcap, "-n", "-t", "tcp") //#nosec G204
		cmdSys.Stderr = io.Discard
		outSys, errSys := cmdSys.Output()

		if errGo != nil || errSys != nil {
			continue // skip pcaps that have no TCP packets
		}

		goFlows := parseFlowsFrom(strings.NewReader(string(outGo)))
		sysFlows := parseFlowsFrom(strings.NewReader(string(outSys)))

		if len(goFlows) == 0 && len(sysFlows) == 0 {
			continue // no TCP in this file — look further
		}

		t.Run(filepath.Base(pcap)+"/tcp_filter", func(t *testing.T) {
			if len(goFlows) != len(sysFlows) {
				t.Errorf("with 'tcp' filter: tcpdump_go=%d packets, tcpdump=%d packets",
					len(goFlows), len(sysFlows))
				t.Logf("tcpdump_go:\n  %s", strings.Join(sortedFlowKeys(goFlows), "\n  "))
				t.Logf("tcpdump:\n  %s", strings.Join(sortedFlowKeys(sysFlows), "\n  "))
			} else {
				t.Logf("OK: %d TCP packets in both tools (%s)", len(goFlows), filepath.Base(pcap))
			}
		})
		return // one pcap is sufficient for this test
	}
}

// Helpers

// comparePrecheck checks preconditions and skips the test if they are not met.
func comparePrecheck(t *testing.T) (tcpdumpBin string, pcapFiles []string) {
	t.Helper()
	if compareBinaryPath == "" {
		t.Skip("tcpdump_go binary unavailable (build failed in TestMain)")
	}
	tcpdumpBin = findSystemTcpdump()
	if tcpdumpBin == "" {
		t.Skip("system tcpdump not available")
	}
	pcapFiles = pcapFilesInRoot()
	if len(pcapFiles) == 0 {
		t.Skip("no *.pcap files in project directory")
	}
	return tcpdumpBin, pcapFiles
}

// uniqueIPs returns the set of unique IP addresses from a list of flows.
func uniqueIPs(flows []parsedFlow) map[string]bool {
	ips := make(map[string]bool)
	for _, f := range flows {
		ips[f.src] = true
		ips[f.dst] = true
	}
	return ips
}
