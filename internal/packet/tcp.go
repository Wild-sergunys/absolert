// Package packet преобразует сетевые заголовки в собственные значения сенсора.
package packet

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	ErrUnsupported = errors.New("неподдерживаемый пакет")
	ErrMalformed   = errors.New("повреждённый или неполный пакет")
)

// Flags содержит девять управляющих битов TCP в порядке их расположения в заголовке.
type Flags uint16

const (
	FIN Flags = 1 << iota
	SYN
	RST
	PSH
	ACK
	URG
	ECE
	CWR
	NS
)

func (f Flags) String() string {
	var names []string
	for i, name := range [...]string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS"} {
		if f&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, "|")
}

// TCP не хранит ссылок на исходный буфер захвата.
type TCP struct {
	Time        time.Time
	Source      netip.AddrPort
	Destination netip.AddrPort
	Flags       Flags
}

type feedback struct{ truncated bool }

func (f *feedback) SetTruncated() { f.truncated = true }

// DecodeTCP поддерживает Ethernet без VLAN и нефрагментированный IPv4/TCP.
// Контрольные суммы здесь не проверяются: захват на хосте может предшествовать offload NIC.
func DecodeTCP(data []byte, timestamp time.Time) (TCP, error) {
	var eth layers.Ethernet
	var fb feedback
	if err := eth.DecodeFromBytes(data, &fb); err != nil {
		return TCP{}, fmt.Errorf("%w: Ethernet: %v", ErrMalformed, err)
	}
	if eth.EthernetType != layers.EthernetTypeIPv4 {
		return TCP{}, ErrUnsupported
	}
	var ip layers.IPv4
	if err := ip.DecodeFromBytes(eth.Payload, &fb); err != nil {
		return TCP{}, fmt.Errorf("%w: IPv4: %v", ErrMalformed, err)
	}
	if fb.truncated || ip.Version != 4 {
		return TCP{}, ErrMalformed
	}
	if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
		return TCP{}, ErrUnsupported
	}
	if ip.Protocol != layers.IPProtocolTCP {
		return TCP{}, ErrUnsupported
	}
	var tcp layers.TCP
	if err := tcp.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback); err != nil {
		return TCP{}, fmt.Errorf("%w: TCP: %v", ErrMalformed, err)
	}
	src, ok := netip.AddrFromSlice(ip.SrcIP)
	if !ok {
		return TCP{}, ErrMalformed
	}
	dst, ok := netip.AddrFromSlice(ip.DstIP)
	if !ok {
		return TCP{}, ErrMalformed
	}
	return TCP{
		Time:        timestamp,
		Source:      netip.AddrPortFrom(src.Unmap(), uint16(tcp.SrcPort)),
		Destination: netip.AddrPortFrom(dst.Unmap(), uint16(tcp.DstPort)),
		Flags:       Flags(ip.Payload[13]) | Flags(ip.Payload[12]&1)<<8,
	}, nil
}
