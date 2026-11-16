package sensor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type readResult struct {
	data []byte
	info gopacket.CaptureInfo
	err  error
}
type testReader struct{ results []readResult }

func (r *testReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if len(r.results) == 0 {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	v := r.results[0]
	r.results = r.results[1:]
	return v.data, v.info, v.err
}

func tcpFrame(t *testing.T) []byte {
	t.Helper()
	b := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}, Protocol: layers.IPProtocolTCP},
		&layers.TCP{SrcPort: 40000, DstPort: 8088, SYN: true},
		gopacket.Payload([]byte("private-test-payload")))
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestProcess(t *testing.T) {
	b := tcpFrame(t)
	unsupported := bytes.Clone(b)
	unsupported[12] = 0x86
	unsupported[13] = 0xdd
	reader := &testReader{results: []readResult{
		{err: pcap.NextErrorTimeoutExpired},
		{data: b, info: gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b)}},
		{data: unsupported, info: gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b)}},
		{data: []byte{1}, info: gopacket.CaptureInfo{CaptureLength: 1, Length: 1}},
		{data: b[:20], info: gopacket.CaptureInfo{CaptureLength: 20, Length: len(b)}},
	}}
	var out bytes.Buffer
	got, err := process(context.Background(), reader, &out)
	if err != nil {
		t.Fatal(err)
	}
	if want := (counts{Read: 4, TCP: 1, Unsupported: 1, Malformed: 1, Truncated: 1}); got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
	if !strings.Contains(out.String(), "192.0.2.1:40000 -> 192.0.2.2:8088 flags=SYN") {
		t.Fatalf("output = %q", out.String())
	}
	if strings.Contains(out.String(), "private-test-payload") {
		t.Fatal("output exposes packet payload")
	}
}

type cancelReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *cancelReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	r.calls++
	r.cancel()
	return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
}

func TestProcessCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancelReader{cancel: cancel}
	_, err := process(ctx, r, io.Discard)
	if !errors.Is(err, context.Canceled) || r.calls != 1 {
		t.Fatalf("error = %v, reads = %d", err, r.calls)
	}
	// Отменённый контекст не должен инициировать ещё одно чтение.
	r.calls = 0
	_, err = process(ctx, r, io.Discard)
	if !errors.Is(err, context.Canceled) || r.calls != 0 {
		t.Fatalf("error = %v, reads = %d", err, r.calls)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestProcessErrors(t *testing.T) {
	b := tcpFrame(t)
	tests := []struct {
		name   string
		result readResult
		writer io.Writer
		want   error
	}{
		{"read", readResult{err: io.ErrUnexpectedEOF}, io.Discard, io.ErrUnexpectedEOF},
		{"write", readResult{data: b, info: gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b)}}, brokenWriter{}, io.ErrClosedPipe},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := process(context.Background(), &testReader{results: []readResult{tt.result}}, tt.writer)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// Уже отменённый запуск не должен открывать даже несуществующий интерфейс.
func TestRunCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, "not-an-interface", io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}
