package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/wild-sergunys/absolert/internal/monitor"
)

func TestReplayETRulesToMonitorAPI(t *testing.T) {
	detector := newReplayDetector(t)
	socketPath := filepath.Join(t.TempDir(), "sensor.sock")
	receiver, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	var store monitor.Store
	receiverDone := make(chan error, 1)
	go func() { receiverDone <- store.Receive(receiver) }()
	t.Cleanup(func() {
		_ = receiver.Close()
		if err := <-receiverDone; !errors.Is(err, net.ErrClosed) {
			t.Errorf("приём из Unix-сокета: %v", err)
		}
	})

	mux := http.NewServeMux()
	mux.Handle("GET /api/monitor", &store)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	publisher, err := monitor.OpenPublisher(socketPath, monitor.Replay)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := Run(ctx, "", "testdata/et-tcp-scan.pcap", io.Discard, detector, publisher); err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/monitor", nil)
	if err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("GET /api/monitor: %v", err)
		}
		var snapshot struct {
			Alerts []monitor.Alert `json:"alerts"`
			Status *monitor.Status `json:"status"`
		}
		err = json.NewDecoder(response.Body).Decode(&snapshot)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("ответ API: HTTP %d, декодирование JSON: %v", response.StatusCode, err)
		}
		if snapshot.Status != nil && !snapshot.Status.Running {
			wantStatus := monitor.Status{Mode: monitor.Replay, Result: monitor.Complete, Read: 32, TCP: 32, Alerts: 8}
			if *snapshot.Status != wantStatus {
				t.Fatalf("итоговый статус API = %+v, ожидалось %+v", *snapshot.Status, wantStatus)
			}
			got := make(map[uint32]int)
			for _, alert := range snapshot.Alerts {
				if alert.Mode != monitor.Replay {
					t.Errorf("SID %d: режим = %q, ожидался %q", alert.SID, alert.Mode, monitor.Replay)
				}
				got[alert.SID]++
			}
			want := map[uint32]int{2002910: 1, 2001219: 1, 2010939: 6}
			if !maps.Equal(got, want) {
				t.Fatalf("алерты API по SID = %v, ожидались %v", got, want)
			}
			t.Logf("API получил 8 алертов, VNC — %d, SSH — %d, PostgreSQL — %d", got[2002910], got[2001219], got[2010939])
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("API не получил итоговый статус прогона PCAP")
		case <-ticker.C:
		}
	}
}
