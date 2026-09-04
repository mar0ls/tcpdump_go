package capture

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/gopacket/gopacket/pcap"
)

func TestPrintCaptureSummaryMatchesTcpdumpWording(t *testing.T) {
	var out bytes.Buffer
	stats := &pcap.Stats{PacketsReceived: 120, PacketsDropped: 7}
	if err := printCaptureSummary(&out, 100, stats); err != nil {
		t.Fatal(err)
	}
	want := "100 packets captured\n120 packets received by filter\n7 packets dropped by kernel\n"
	if out.String() != want {
		t.Fatalf("summary =\n%q\nwant\n%q", out.String(), want)
	}
}

// A libpcap that cannot report kernel counters must not have them invented as
// zeros, so only the locally known count is printed.
func TestPrintCaptureSummaryWithoutKernelCounters(t *testing.T) {
	var out bytes.Buffer
	if err := printCaptureSummary(&out, 3, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "3 packets captured\n" {
		t.Fatalf("summary = %q", out.String())
	}
	if strings.Contains(out.String(), "dropped") {
		t.Fatal("kernel counters were printed without libpcap statistics")
	}
}

// Some platforms report negative counters when a value is unavailable.
func TestPrintCaptureSummaryClampsNegativeCounters(t *testing.T) {
	var out bytes.Buffer
	if err := printCaptureSummary(&out, 0, &pcap.Stats{PacketsReceived: -1, PacketsDropped: -1}); err != nil {
		t.Fatal(err)
	}
	want := "0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n"
	if out.String() != want {
		t.Fatalf("summary = %q, want %q", out.String(), want)
	}
}

func TestPrintCaptureSummaryReportsWriteErrors(t *testing.T) {
	if err := printCaptureSummary(failingWriter{}, 1, &pcap.Stats{}); err == nil {
		t.Fatal("printCaptureSummary ignored a write error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestShutdownSignalsIncludeSIGHUP(t *testing.T) {
	var names []string
	for _, signal := range ShutdownSignals {
		names = append(names, signal.String())
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"interrupt", "terminated", "hangup"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ShutdownSignals = %s, missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "quit") {
		t.Errorf("ShutdownSignals = %s: SIGQUIT must stay available for stack dumps", joined)
	}
}
