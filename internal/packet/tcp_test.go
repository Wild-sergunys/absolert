package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// frame — синтетический Ethernet/IPv4/TCP-пакет без пользовательского трафика.
func frame() []byte {
	b := make([]byte, 54)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:18], 40)
	b[22], b[23] = 64, 6
	copy(b[26:30], []byte{192, 0, 2, 1})
	copy(b[30:34], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(b[34:36], 40000)
	binary.BigEndian.PutUint16(b[36:38], 8088)
	b[46], b[47] = 0x50, 0x12
	return b
}

func TestDecodeTCP(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name    string
		change  func([]byte) []byte
		wantErr error
	}{
		{name: "syn_ack"},
		{name: "short_ethernet", change: func(b []byte) []byte { return b[:13] }, wantErr: ErrMalformed},
		{name: "short_ipv4", change: func(b []byte) []byte { return b[:25] }, wantErr: ErrMalformed},
		{name: "short_tcp", change: func(b []byte) []byte { return b[:50] }, wantErr: ErrMalformed},
		{name: "invalid_ip_version", change: func(b []byte) []byte { b[14] = 0x65; return b }, wantErr: ErrMalformed},
		{name: "invalid_ip_length", change: func(b []byte) []byte { b[17] = 19; return b }, wantErr: ErrMalformed},
		{name: "invalid_tcp_offset", change: func(b []byte) []byte { b[46] = 0x40; return b }, wantErr: ErrMalformed},
		{name: "ipv6", change: func(b []byte) []byte { b[12] = 0x86; b[13] = 0xdd; return b }, wantErr: ErrUnsupported},
		{name: "vlan", change: func(b []byte) []byte { b[12] = 0x81; b[13] = 0; return b }, wantErr: ErrUnsupported},
		{name: "udp", change: func(b []byte) []byte { b[23] = 17; return b }, wantErr: ErrUnsupported},
		{name: "first_fragment", change: func(b []byte) []byte { b[20] = 0x20; return b }, wantErr: ErrUnsupported},
		{name: "later_fragment", change: func(b []byte) []byte { b[21] = 1; return b }, wantErr: ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := frame()
			if tt.change != nil {
				b = tt.change(b)
			}
			got, err := DecodeTCP(b, now)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			want := TCP{Time: now, Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("192.0.2.2:8088"), Flags: SYN | ACK}
			if got != want {
				t.Fatalf("TCP = %+v, want %+v", got, want)
			}
			// Наблюдение не заимствует адреса из буфера следующего чтения.
			clear(b)
			if got != want {
				t.Fatal("observation changed with source buffer")
			}
			if got.Flags.String() != "SYN|ACK" {
				t.Errorf("flags = %q", got.Flags)
			}
		})
	}
}

func FuzzDecodeTCP(f *testing.F) {
	f.Add(frame())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeTCP(b, time.Time{}) })
}

func TestFlags(t *testing.T) {
	tests := []struct {
		name string
		bits byte
		ns   byte
		want Flags
		text string
	}{
		{"no_flags", 0, 0, 0, "-"},
		{"reset", 4, 0, RST, "RST"},
		{"all_flags", 255, 1, FIN | SYN | RST | PSH | ACK | URG | ECE | CWR | NS, "FIN|SYN|RST|PSH|ACK|URG|ECE|CWR|NS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := frame()
			b[46] |= tt.ns
			b[47] = tt.bits
			got, err := DecodeTCP(b, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Flags != tt.want || got.Flags.String() != tt.text {
				t.Fatalf("flags = %d (%q), want %d (%q)", got.Flags, got.Flags.String(), tt.want, tt.text)
			}
		})
	}
}
