package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/wild-sergunys/absolert/internal/packet"
	"github.com/wild-sergunys/absolert/internal/rules"
)

func testDetector(t *testing.T, flags, mode string, count uint32) *TCP {
	t.Helper()
	rule := rules.Rule{
		SID: 2002910, Revision: 6, Flags: flags, ToServer: true,
		Source:      rules.Endpoint{Network: "$EXTERNAL_NET", Ports: rules.PortRange{First: 1024, Last: 65535}},
		Destination: rules.Endpoint{Network: "$HOME_NET", Ports: rules.PortRange{First: 5800, Last: 5820}},
		Threshold:   rules.Threshold{Type: mode, Track: "by_src", Count: count, Seconds: 60},
	}
	detector, err := NewTCP([]rules.Rule{rule}, netip.MustParsePrefix("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func TestObserveThreshold(t *testing.T) {
	detector := testDetector(t, "S,12", "both", 2)
	first := netip.MustParseAddrPort("198.51.100.1:40000")
	second := netip.MustParseAddrPort("198.51.100.2:40000")
	target := netip.MustParseAddrPort("192.0.2.1:5800")
	start := time.Unix(100, 0)
	const window = 60 * time.Second
	steps := []struct {
		name        string
		offset      time.Duration
		source      netip.AddrPort
		destination netip.AddrPort
		flags       packet.Flags
		alert       bool
	}{
		{"first match", 0, first, target, packet.SYN, false},
		{"different IP has its own window", 0, second, target, packet.SYN, false},
		{"SYN-ACK is not an initial SYN", time.Second, first, target, packet.SYN | packet.ACK, false},
		{"reverse direction", time.Second, target, first, packet.SYN, false},
		{"unmonitored source port", time.Second, netip.AddrPortFrom(first.Addr(), 80), target, packet.SYN, false},
		{"unmonitored destination port", time.Second, first, netip.AddrPortFrom(target.Addr(), 5821), packet.SYN, false},
		{"first match already counted for the other IP", 2 * time.Second, second, target, packet.SYN, true},
		{"inclusive boundary and ECN", window, first, target, packet.SYN | packet.ECE | packet.CWR, true},
		{"suppress further alerts", window, first, target, packet.SYN, false},
		{"discard backwards timestamp", window - time.Second, first, target, packet.SYN, false},
		{"reset after boundary", window + time.Nanosecond, first, target, packet.SYN, false},
		{"count by IP across source ports and destinations", window + time.Second,
			netip.AddrPortFrom(first.Addr(), 40001), netip.MustParseAddrPort("192.0.2.2:5820"), packet.SYN, true},
	}
	for _, step := range steps {
		got := detector.Observe(packet.TCP{Time: start.Add(step.offset), Source: step.source, Destination: step.destination, Flags: step.flags})
		if (len(got) == 1) != step.alert {
			t.Fatalf("%s: got %d alerts, want alert=%t", step.name, len(got), step.alert)
		}
	}
	if skipped := detector.Stats().OutOfOrder; skipped != 1 {
		t.Fatalf("out-of-order packets = %d, want 1", skipped)
	}
}

func TestLimitWindow(t *testing.T) {
	detector := testDetector(t, "S", "limit", 2)
	start := time.Unix(100, 0)
	observation := packet.TCP{
		Source:      netip.MustParseAddrPort("198.51.100.1:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.1:5800"),
		Flags:       packet.SYN,
	}
	const window = 60 * time.Second
	for _, step := range []struct {
		offset time.Duration
		count  uint32
	}{{0, 1}, {window, 2}, {window, 0}, {window + time.Microsecond, 1}} {
		observation.Time = start.Add(step.offset)
		got := detector.Observe(observation)
		if step.count == 0 {
			if len(got) != 0 {
				t.Fatalf("at %s: alerts = %+v, want suppression", step.offset, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Count != step.count {
			t.Fatalf("at %s: alerts = %+v, want one alert with count %d", step.offset, got, step.count)
		}
	}
}

func TestObserveExactSYNAndCapacity(t *testing.T) {
	detector := testDetector(t, "S", "both", 1)
	observation := packet.TCP{
		Time:        time.Unix(100, 0),
		Source:      netip.MustParseAddrPort("198.51.100.1:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.1:5800"),
		Flags:       packet.SYN | packet.ECE,
	}
	if got := detector.Observe(observation); len(got) != 0 {
		t.Fatal("flags:S matched an ECE bit")
	}
	observation.Flags = packet.SYN
	for index := range maxWindows {
		source := netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index & 255)})
		observation.Source = netip.AddrPortFrom(source, 40000)
		if got := detector.Observe(observation); len(got) != 1 {
			t.Fatalf("limit reached early: source %d", index)
		}
	}
	observation.Source = netip.MustParseAddrPort("198.51.100.1:40000")
	if got := detector.Observe(observation); len(got) != 0 || detector.Stats().StateLimit != 1 {
		t.Fatal("new source should be rejected and counted when the state is full")
	}
	observation.Time = observation.Time.Add(61 * time.Second)
	if got := detector.Observe(observation); len(got) != 1 || len(detector.windows) != 1 {
		t.Fatal("expired state should free capacity for the next match")
	}
}
