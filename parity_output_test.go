package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestByteForByteParityWithTcpdump compares complete rendered output, not just
// parsed flows: every fixture is printed at each verbosity level by both tools
// and the text must match exactly. The fixtures cover the application-layer
// printers (DNS, HTTP, NTP), ARP, checksum verification, and the -v/-vv/-vvv
// detail levels, which are the places where wording drifts most easily.
//
// The comparison is against whatever tcpdump is installed, and builds differ:
// verified against Apple 4.99.1 on macOS and 4.99.4 on Rocky Linux, with the
// fixtures kept to output both agree on.
func TestByteForByteParityWithTcpdump(t *testing.T) {
	tcpdumpBin, _ := comparePrecheck(t)

	directory := t.TempDir()
	fixtures := buildParityFixtures(t, directory)
	levels := [][]string{{}, {"-v"}, {"-vv"}, {"-vvv"}, {"-e"}, {"-q"}, {"-e", "-q"}, {"-e", "-v"}}

	for _, fixture := range fixtures {
		path := filepath.Join(directory, fixture)
		for _, level := range levels {
			name := fixture
			if len(level) > 0 {
				name += " " + strings.Join(level, " ")
			}
			t.Run(name, func(t *testing.T) {
				// -nn, not -n: Apple's tcpdump fork suppresses port names with
				// a single -n where upstream, which this follows, still
				// resolves them. -nn means the same thing in every build.
				args := append([]string{"-nnr", path, "-t"}, level...)
				want := runTool(t, tcpdumpBin, args)
				got := runTool(t, compareBinaryPath, append(args, "--color", "never"))
				if got != want {
					t.Fatalf("output differs\n--- tcpdump_go ---\n%s\n--- tcpdump ---\n%s", got, want)
				}
			})
		}
	}
}

func runTool(t *testing.T, binary string, args []string) string {
	t.Helper()
	output, err := exec.Command(binary, args...).Output() //#nosec G204 // fixed test binaries and fixture paths
	if err != nil {
		t.Fatalf("%s %v: %v", binary, args, err)
	}
	return string(output)
}
