// Package capture отвечает за открытие источника пакетов и настройки libpcap.
package capture

import (
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Open открывает захват без promiscuous mode для первого стенда с локальной целью.
// Конечное ожидание чтения позволяет циклу проверять отмену даже без новых пакетов.
func Open(device string) (*pcap.Handle, error) {
	if strings.TrimSpace(device) == "" {
		return nil, fmt.Errorf("сетевой интерфейс не указан")
	}
	h, err := pcap.OpenLive(device, 65535, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("открытие захвата на %q: %w", device, err)
	}
	if link := h.LinkType(); link != layers.LinkTypeEthernet {
		h.Close()
		return nil, fmt.Errorf("неподдерживаемый тип канального уровня %s: требуется Ethernet", link)
	}
	// Без BPF на этом этапе: счётчики должны учитывать и неподдерживаемые пакеты.
	return h, nil
}
