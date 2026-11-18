package monitor

import (
	"encoding/json"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestPublisherWithoutAndWithReceiver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sensor.sock")
	publisher, err := OpenPublisher(path, Replay)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	alert := Alert{SID: 2002910, Time: time.Unix(100, 0)}
	publisher.Alert(alert)
	if publisher.Dropped() != 1 {
		t.Fatal("failed delivery was not counted")
	}
	receiver, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	publisher.Status(Status{Running: true, Read: 8})
	buffer := make([]byte, maxBytes)
	length, _, err := receiver.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var reported update
	if err := json.Unmarshal(buffer[:length], &reported); err != nil {
		t.Fatal(err)
	}
	if reported.Status == nil || *reported.Status != (Status{Running: true, Mode: Replay, Read: 8, Dropped: 1}) {
		t.Fatalf("unexpected status: %+v", reported.Status)
	}
}

func TestStoreBoundsAndFreshness(t *testing.T) {
	var store Store
	now := time.Unix(100, 0)
	alert := Alert{
		SID: 2002910, Time: now, Mode: Live,
		Source:      netip.MustParseAddrPort("192.0.2.1:40000"),
		Destination: netip.MustParseAddrPort("192.0.2.2:5800"),
	}
	for range historyLimit + 1 {
		store.add(update{Alert: &alert}, now)
	}
	store.add(update{Status: &Status{Mode: Live, Running: true}}, now)
	current := store.snapshot(now.Add(3 * time.Second))
	if !current.Fresh || len(current.Alerts) != historyLimit || current.Alerts[0].ID != historyLimit+1 ||
		current.Alerts[historyLimit-1].ID != 2 {
		t.Fatalf("unexpected history: fresh=%t, count=%d", current.Fresh, len(current.Alerts))
	}
	if expired := store.snapshot(now.Add(4 * time.Second)); expired.Fresh || expired.Status == nil {
		t.Fatal("expired status should be retained and marked as stale")
	}
}
