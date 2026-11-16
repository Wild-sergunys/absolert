// Package sensor связывает источник пакетов, декодирование и диагностический вывод.
package sensor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/wild-sergunys/absolert/internal/capture"
	"github.com/wild-sergunys/absolert/internal/packet"
)

// packetReader позволяет проверять тот же цикл без интерфейса и прав захвата.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type counts struct{ Read, TCP, Unsupported, Malformed, Truncated uint64 }

// Run владеет захватом и закрывает его после завершения обработки.
func Run(ctx context.Context, device string, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h, err := capture.Open(device)
	if err != nil {
		return err
	}
	defer h.Close()
	if _, err = fmt.Fprintf(out, "Захват на %q: Ethernet / IPv4 / TCP. Ctrl+C — остановка.\n", device); err != nil {
		return fmt.Errorf("вывод статуса: %w", err)
	}
	c, runErr := process(ctx, h, out)
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	_, printErr := fmt.Fprintf(out, "Прочитано: %d | TCP: %d | Неподдерживаемые: %d | Повреждённые: %d | Усечённые: %d\n", c.Read, c.TCP, c.Unsupported, c.Malformed, c.Truncated)
	stats, statsErr := h.Stats()
	if statsErr == nil {
		_, err = fmt.Fprintf(out, "libpcap: получено=%d | потеряно в буфере=%d | потеряно интерфейсом=%d\n", stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
		printErr = errors.Join(printErr, err)
	} else {
		statsErr = fmt.Errorf("статистика libpcap: %w", statsErr)
	}
	return errors.Join(runErr, printErr, statsErr)
}

func process(ctx context.Context, reader packetReader, out io.Writer) (counts, error) {
	var c counts
	for {
		if err := ctx.Err(); err != nil {
			return c, err
		}
		data, info, err := reader.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return c, nil
			}
			return c, fmt.Errorf("чтение пакета: %w", err)
		}
		c.Read++
		if info.CaptureLength < info.Length {
			c.Truncated++
			continue
		}
		tcp, err := packet.DecodeTCP(data, info.Timestamp)
		switch {
		case errors.Is(err, packet.ErrUnsupported):
			c.Unsupported++
			continue
		case err != nil:
			c.Malformed++
			continue
		}
		c.TCP++
		// shortcut: построчный вывод ограничивает скорость; заменить агрегатами на этапе веба.
		if _, err := fmt.Fprintf(out, "%s %s -> %s flags=%s\n", tcp.Time.Format(time.RFC3339Nano), tcp.Source, tcp.Destination, tcp.Flags); err != nil {
			return c, fmt.Errorf("вывод TCP: %w", err)
		}
	}
}
