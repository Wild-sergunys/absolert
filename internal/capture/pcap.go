// Package capture отвечает за открытие источника пакетов и настройки libpcap.
package capture

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Open открывает захват без promiscuous mode.
// Конечное ожидание чтения позволяет циклу проверять отмену даже без новых пакетов.
func Open(device string) (*pcap.Handle, error) {
	if strings.TrimSpace(device) == "" {
		return nil, fmt.Errorf("сетевой интерфейс не указан")
	}
	h, err := pcap.OpenLive(device, 65535, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("открытие захвата на %q: %w", device, err)
	}
	// Счётчики учитывают и неподдерживаемые пакеты, поэтому BPF не ставится.
	return requireEthernet(h)
}

func OpenFile(path string) (*pcap.Handle, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("открытие PCAP %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("проверка PCAP %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("PCAP %q должен быть обычным файлом", path)
	}
	h, err := pcap.OpenOfflineFile(file)
	if err != nil {
		return nil, fmt.Errorf("чтение заголовка PCAP %q: %w", path, err)
	}
	return requireEthernet(h)
}

func requireEthernet(h *pcap.Handle) (*pcap.Handle, error) {
	if link := h.LinkType(); link != layers.LinkTypeEthernet {
		h.Close()
		return nil, fmt.Errorf("неподдерживаемый тип канального уровня %s: требуется Ethernet", link)
	}
	return h, nil
}
