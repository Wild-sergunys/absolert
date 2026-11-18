package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenFileRejectsInvalidCapture(t *testing.T) {
	fixture, err := os.ReadFile("../sensor/testdata/et-tcp-scan.pcap")
	if err != nil {
		t.Fatal(err)
	}
	wrongLink := fixture[:24]
	wrongLink[20] = 101
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{"damaged header", fixture[:8], "чтение заголовка PCAP"},
		{"non-Ethernet", wrongLink, "требуется Ethernet"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.pcap")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			handle, err := OpenFile(path)
			if handle != nil {
				handle.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
