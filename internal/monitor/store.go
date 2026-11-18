package monitor

import (
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

const historyLimit = 100

type Store struct {
	mu        sync.Mutex
	alerts    []Alert
	status    *Status
	updatedAt time.Time
	nextID    uint64
}

type snapshot struct {
	Alerts    []Alert   `json:"alerts"`
	Status    *Status   `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
	Fresh     bool      `json:"fresh"`
}

func (store *Store) Receive(conn *net.UnixConn) error {
	buffer := make([]byte, maxBytes+1)
	for {
		length, _, err := conn.ReadFromUnix(buffer)
		if err != nil {
			return err
		}
		var message update
		if length > maxBytes || json.Unmarshal(buffer[:length], &message) != nil {
			continue
		}
		store.add(message, time.Now())
	}
}

func (store *Store) add(message update, now time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()
	switch {
	case message.Alert != nil && message.Status == nil:
		alert := *message.Alert
		if (alert.Mode != Live && alert.Mode != Replay) || alert.SID == 0 || alert.Time.IsZero() ||
			!alert.Source.IsValid() || !alert.Destination.IsValid() {
			return
		}
		store.nextID++
		alert.ID = store.nextID
		if len(store.alerts) == historyLimit {
			copy(store.alerts, store.alerts[1:])
			store.alerts = store.alerts[:historyLimit-1]
		}
		store.alerts = append(store.alerts, alert)
	case message.Status != nil && message.Alert == nil:
		if message.Status.Mode == Live || message.Status.Mode == Replay {
			status := *message.Status
			store.status = &status
			store.updatedAt = now
		}
	}
}

func (store *Store) snapshot(now time.Time) snapshot {
	store.mu.Lock()
	defer store.mu.Unlock()
	alerts := make([]Alert, len(store.alerts))
	copy(alerts, store.alerts)
	slices.Reverse(alerts)
	return snapshot{
		Alerts: alerts, Status: store.status, UpdatedAt: store.updatedAt,
		Fresh: store.status != nil && now.Sub(store.updatedAt) < 4*time.Second,
	}
}

func (store *Store) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(store.snapshot(time.Now()))
}
