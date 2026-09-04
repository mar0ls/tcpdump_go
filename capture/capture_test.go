package capture

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
