package monitor

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	Live     = "live"
	Replay   = "pcap"
	Complete = "complete"
	Failed   = "failed"
	maxBytes = 16 << 10
)

type Alert struct {
	ID          uint64         `json:"id,omitempty"`
	Time        time.Time      `json:"time"`
	Mode        string         `json:"mode"`
	Source      netip.AddrPort `json:"source"`
	Destination netip.AddrPort `json:"destination"`
	SID         uint32         `json:"sid"`
	Revision    uint32         `json:"revision"`
	Message     string         `json:"message"`
	Flags       string         `json:"flags"`
	Threshold   string         `json:"threshold"`
	Count       uint32         `json:"count"`
	Limit       uint32         `json:"limit"`
	Seconds     uint32         `json:"seconds"`
}

type Status struct {
	Mode    string `json:"mode"`
	Running bool   `json:"running"`
	Result  string `json:"result,omitempty"`
	Read    uint64 `json:"read"`
	TCP     uint64 `json:"tcp"`
	Alerts  uint64 `json:"alerts"`
	Dropped uint64 `json:"dropped"`
}

type update struct {
	Alert  *Alert  `json:"alert,omitempty"`
	Status *Status `json:"status,omitempty"`
}

type Publisher struct {
	fd      int
	address syscall.SockaddrUnix
	mode    string
	dropped uint64
}

func OpenPublisher(path, mode string) (*Publisher, error) {
	if !filepath.IsAbs(path) || len(path) >= 108 || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("нужен абсолютный путь к Unix-сокету короче 108 байт")
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("сокет отправки: %w", err)
	}
	return &Publisher{fd: fd, address: syscall.SockaddrUnix{Name: path}, mode: mode}, nil
}

func (publisher *Publisher) Close() { _ = syscall.Close(publisher.fd) }

func (publisher *Publisher) Alert(alert Alert) {
	alert.Mode = publisher.mode
	if !publisher.send(update{Alert: &alert}) {
		publisher.dropped++
	}
}

func (publisher *Publisher) Status(status Status) {
	status.Mode = publisher.mode
	status.Dropped = publisher.dropped
	publisher.send(update{Status: &status})
}

func (publisher *Publisher) Dropped() uint64 { return publisher.dropped }

func (publisher *Publisher) send(message update) bool {
	data, err := json.Marshal(message)
	if err != nil || len(data) > maxBytes {
		return false
	}
	return syscall.Sendto(publisher.fd, data, syscall.MSG_DONTWAIT, &publisher.address) == nil
}
