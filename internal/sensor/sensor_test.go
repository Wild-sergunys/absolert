package sensor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/wild-sergunys/absolert/internal/detect"
	"github.com/wild-sergunys/absolert/internal/rules"
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

func tcpFrame(t *testing.T, destination layers.TCPPort) []byte {
	t.Helper()
	b := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}, Protocol: layers.IPProtocolTCP},
		&layers.TCP{SrcPort: 40000, DstPort: destination, SYN: true},
		gopacket.Payload([]byte("private-test-payload")))
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestProcess(t *testing.T) {
	b := tcpFrame(t, 8088)
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
	got, err := process(context.Background(), reader, &out, nil, nil)
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

func TestReplayETRules(t *testing.T) {
	file, err := os.Open("../../configs/rules/et-tcp-scan.rules")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := rules.Load(file)
	if err := errors.Join(err, file.Close()); err != nil {
		t.Fatal(err)
	}
	detector, err := detect.NewTCP(loaded, netip.MustParsePrefix("192.0.2.2/32"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	if err := Run(context.Background(), "", "testdata/et-tcp-scan.pcap", &out, detector, nil); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		offset        time.Duration
		id            string
		count, window int
	}{
		{0, "2010939:3", 1, 60},
		{time.Second, "2010939:3", 2, 60},
		{2 * time.Second, "2010939:3", 3, 60},
		{3 * time.Second, "2010939:3", 4, 60},
		{4 * time.Second, "2002910:6", 5, 60},
		{4 * time.Second, "2001219:20", 5, 120},
		{4 * time.Second, "2010939:3", 5, 60},
		{time.Minute + time.Microsecond, "2010939:3", 1, 60},
	}
	var lines []string
	for line := range strings.SplitSeq(out.String(), "\n") {
		if strings.HasPrefix(line, "АЛЕРТ ") {
			lines = append(lines, line)
		}
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d alerts, want %d:\n%s", len(lines), len(want), &out)
	}
	for index, alert := range want {
		timestamp := start.Add(alert.offset).Local().Format(time.RFC3339Nano)
		prefix := fmt.Sprintf("АЛЕРТ %s [%s]", timestamp, alert.id)
		suffix := fmt.Sprintf("совпадений=%d окно=%dс", alert.count, alert.window)
		if !strings.HasPrefix(lines[index], prefix) || !strings.HasSuffix(lines[index], suffix) {
			t.Errorf("alert %d = %q; want prefix %q and suffix %q", index, lines[index], prefix, suffix)
		}
	}
	if output := out.String(); !strings.Contains(output, "Прочитано: 32 | TCP: 32") ||
		!strings.Contains(output, "Алерты: 8 |") || strings.Contains(output, "libpcap:") {
		t.Fatalf("unexpected replay summary:\n%s", output)
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
	_, err := process(ctx, r, io.Discard, nil, nil)
	if !errors.Is(err, context.Canceled) || r.calls != 1 {
		t.Fatalf("error = %v, reads = %d", err, r.calls)
	}
	// Отменённый контекст не должен инициировать ещё одно чтение.
	r.calls = 0
	_, err = process(ctx, r, io.Discard, nil, nil)
	if !errors.Is(err, context.Canceled) || r.calls != 0 {
		t.Fatalf("error = %v, reads = %d", err, r.calls)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestProcessErrors(t *testing.T) {
	b := tcpFrame(t, 8088)
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
			_, err := process(context.Background(), &testReader{results: []readResult{tt.result}}, tt.writer, nil, nil)
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
	if err := Run(ctx, "not-an-interface", "", io.Discard, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}
