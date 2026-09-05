package capture

import (
	"context"
	"errors"
	"io"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type slicePacketReader struct {
	packets []gopacket.Packet
	index   int
	err     error
}

func (r *slicePacketReader) NextPacket() (gopacket.Packet, error) {
	if r.index < len(r.packets) {
		packet := r.packets[r.index]
		r.index++
		return packet, nil
	}
	if r.err != nil {
		return nil, r.err
	}
	return nil, io.EOF
}

func TestRunPacketPipelineHonorsCountAndFlushes(t *testing.T) {
	reader := &slicePacketReader{packets: []gopacket.Packet{testPacket(1), testPacket(2), testPacket(3)}}
	var processed, flushed int
	err := runPacketPipeline(context.Background(), reader, 2, 1, defaultQueueBytes, func(packet capturedPacket) error {
		processed++
		if packet.num != uint64(processed) {
			t.Fatalf("packet number = %d, want %d", packet.num, processed)
		}
		return nil
	}, func() error {
		flushed++
		return nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if processed != 2 || flushed != 2 {
		t.Fatalf("processed/flushed = %d/%d, want 2/2", processed, flushed)
	}
}

func TestRunPacketPipelinePropagatesReadAndProcessErrors(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		want := errors.New("device disappeared")
		reader := &slicePacketReader{err: want}
		err := runPacketPipeline(context.Background(), reader, 0, 1, defaultQueueBytes, func(capturedPacket) error { return nil }, nil, false)
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	})

	t.Run("process", func(t *testing.T) {
		want := errors.New("disk full")
		reader := &slicePacketReader{packets: []gopacket.Packet{testPacket(1), testPacket(2)}}
		err := runPacketPipeline(context.Background(), reader, 2, 1, defaultQueueBytes, func(capturedPacket) error { return want }, nil, false)
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	})
}

func TestRunPacketPipelineCancellationIsGraceful(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &slicePacketReader{err: errors.New("must not be read")}
	if err := runPacketPipeline(ctx, reader, 0, 1, defaultQueueBytes, func(capturedPacket) error { return nil }, nil, false); err != nil {
		t.Fatalf("cancelled pipeline error = %v", err)
	}
}

type sliceRawReader struct {
	packets [][]byte
	index   int
	err     error
	// timeouts are returned before the first packet, as libpcap does when its
	// read timeout expires with an empty buffer.
	timeouts int
}

func (r *sliceRawReader) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if r.timeouts > 0 {
		r.timeouts--
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
	if r.index < len(r.packets) {
		data := r.packets[r.index]
		r.index++
		return data, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, nil
	}
	if r.err != nil {
		return nil, gopacket.CaptureInfo{}, r.err
	}
	return nil, gopacket.CaptureInfo{}, io.EOF
}

func TestRawWriteOnlySelectsTheFastPath(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"write only", Config{OutPcap: "a.pcap", Quiet: true}, true},
		{"no output file", Config{Quiet: true}, false},
		{"also printing", Config{OutPcap: "a.pcap"}, false},
		{"stats requested", Config{OutPcap: "a.pcap", Quiet: true, ShowStats: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawWriteOnly(tc.cfg); got != tc.want {
				t.Fatalf("rawWriteOnly = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunRawWritePipelineHonorsCountAndFlushes(t *testing.T) {
	reader := &sliceRawReader{packets: [][]byte{{1}, {2, 2}, {3, 3, 3}}, timeouts: 2}
	var written [][]byte
	var flushed int
	var captured uint64
	err := runRawWritePipeline(context.Background(), reader, 2, func(ci gopacket.CaptureInfo, data []byte) error {
		if ci.CaptureLength != len(data) {
			t.Fatalf("capture length = %d, want %d", ci.CaptureLength, len(data))
		}
		written = append(written, append([]byte(nil), data...))
		return nil
	}, func() error {
		flushed++
		return nil
	}, true, &captured)
	if err != nil {
		t.Fatal(err)
	}
	if captured != 2 || len(written) != 2 || flushed != 2 {
		t.Fatalf("captured/written/flushed = %d/%d/%d, want 2/2/2", captured, len(written), flushed)
	}
	if string(written[1]) != string([]byte{2, 2}) {
		t.Fatalf("second packet = %v", written[1])
	}
}

func TestRunRawWritePipelinePropagatesErrors(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		want := errors.New("device disappeared")
		var captured uint64
		err := runRawWritePipeline(context.Background(), &sliceRawReader{err: want}, 0,
			func(gopacket.CaptureInfo, []byte) error { return nil }, nil, false, &captured)
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	})

	t.Run("write", func(t *testing.T) {
		want := errors.New("disk full")
		reader := &sliceRawReader{packets: [][]byte{{1}, {2}}}
		var captured uint64
		err := runRawWritePipeline(context.Background(), reader, 0,
			func(gopacket.CaptureInfo, []byte) error { return want }, nil, false, &captured)
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	})

	t.Run("eof is not a clean end for a live capture", func(t *testing.T) {
		var captured uint64
		err := runRawWritePipeline(context.Background(), &sliceRawReader{}, 0,
			func(gopacket.CaptureInfo, []byte) error { return nil }, nil, false, &captured)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error = %v, want io.EOF", err)
		}
	})
}

func TestRunRawWritePipelineCancellationIsGraceful(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &sliceRawReader{err: errors.New("must not be read")}
	var captured uint64
	if err := runRawWritePipeline(ctx, reader, 0,
		func(gopacket.CaptureInfo, []byte) error { return nil }, nil, false, &captured); err != nil {
		t.Fatalf("cancelled pipeline error = %v", err)
	}
	if captured != 0 {
		t.Fatalf("captured = %d, want 0", captured)
	}
}

func TestOpenRawOutputForwardsRotationLimit(t *testing.T) {
	// -W was declared on Config and never passed to the writer, so a live
	// capture rotated without limit while -r honoured it.
	dir := t.TempDir()
	cfg := Config{
		OutPcap:    filepath.Join(dir, "capture.pcap"),
		Snaplen:    defaultSnaplen,
		RotateSize: 200,
		MaxFiles:   3,
	}
	out, err := openRawOutput(cfg, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 120)
	for i := range 20 {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i), 0),
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := out.write(ci, data); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	if err := out.close(); err != nil {
		t.Fatal(err)
	}

	segments, err := filepath.Glob(filepath.Join(dir, "capture*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 3 {
		t.Fatalf("wrote %d segments, want 3 cycling ones: %v", len(segments), segments)
	}
}

func TestLibpcapParametersValidateSignedRanges(t *testing.T) {
	snaplen, buffer, err := libpcapParameters(0, 0)
	if err != nil || snaplen != int(defaultSnaplen) || buffer != int(defaultBufKB)*1024 {
		t.Fatalf("defaults = %d/%d/%v", snaplen, buffer, err)
	}
	if _, _, err := libpcapParameters(math.MaxInt32+1, 1); err == nil || !strings.Contains(err.Error(), "snaplen") {
		t.Fatalf("oversized snaplen error = %v", err)
	}
	if _, _, err := libpcapParameters(1, math.MaxUint32); err == nil || !strings.Contains(err.Error(), "buffer") {
		t.Fatalf("oversized buffer error = %v", err)
	}
}

func TestCaptureQueueDepthIsBounded(t *testing.T) {
	if got := captureQueueDepth(1); got != minCaptureQueue {
		t.Fatalf("small queue = %d", got)
	}
	if got := captureQueueDepth(math.MaxUint32); got != maxCaptureQueue {
		t.Fatalf("large queue = %d", got)
	}
}

func testPacket(second int64) gopacket.Packet {
	packet := gopacket.NewPacket(make([]byte, 14), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(second, 0)
	return packet
}

func TestFlightControlBlocksUntilBytesAreReleased(t *testing.T) {
	budget := newFlightControl(1000)
	if !budget.admit(context.Background(), 600) {
		t.Fatal("first packet was not admitted")
	}
	if !budget.admit(context.Background(), 300) {
		t.Fatal("second packet fit within the budget but was rejected")
	}

	admitted := make(chan bool, 1)
	go func() { admitted <- budget.admit(context.Background(), 500) }()
	select {
	case <-admitted:
		t.Fatal("a packet was admitted past the byte budget")
	case <-time.After(50 * time.Millisecond):
	}

	budget.release(600)
	select {
	case ok := <-admitted:
		if !ok {
			t.Fatal("admit reported failure after room was freed")
		}
	case <-time.After(time.Second):
		t.Fatal("admit did not wake up after bytes were released")
	}
}

// A packet bigger than the whole budget must still go through, alone.
func TestFlightControlAdmitsOversizedPacketAlone(t *testing.T) {
	budget := newFlightControl(1000)
	done := make(chan bool, 1)
	go func() { done <- budget.admit(context.Background(), 5000) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("oversized packet was rejected on an empty queue")
		}
	case <-time.After(time.Second):
		t.Fatal("oversized packet deadlocked the reader")
	}
}

func TestFlightControlUnblocksOnCancel(t *testing.T) {
	budget := newFlightControl(100)
	if !budget.admit(context.Background(), 100) {
		t.Fatal("first packet was not admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- budget.admit(ctx, 100) }()
	cancel()
	select {
	case ok := <-result:
		if ok {
			t.Fatal("admit reported success after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("admit ignored cancellation and blocked forever")
	}
}
