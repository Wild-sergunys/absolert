// Package sensor связывает источник пакетов, декодирование и вывод алертов.
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
	"github.com/wild-sergunys/absolert/internal/detect"
	"github.com/wild-sergunys/absolert/internal/monitor"
	"github.com/wild-sergunys/absolert/internal/packet"
)

// packetReader позволяет проверять тот же цикл без интерфейса и прав захвата.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type counts struct{ Read, TCP, Unsupported, Malformed, Truncated, Alerts uint64 }

func (totals counts) status(running bool) monitor.Status {
	return monitor.Status{Running: running, Read: totals.Read, TCP: totals.TCP, Alerts: totals.Alerts}
}

// Run владеет захватом и закрывает его после завершения обработки.
func Run(ctx context.Context, device, pcapPath string, out io.Writer, detector *detect.TCP, publisher *monitor.Publisher) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var h *pcap.Handle
	var err error
	source := fmt.Sprintf("Захват на %q", device)
	if pcapPath != "" {
		h, err = capture.OpenFile(pcapPath)
		source = fmt.Sprintf("Чтение PCAP %q", pcapPath)
	} else {
		h, err = capture.Open(device)
	}
	if err != nil {
		return err
	}
	defer h.Close()
	if _, err = fmt.Fprintf(out, "%s: Ethernet / IPv4 / TCP. Ctrl+C — остановка.\n", source); err != nil {
		return fmt.Errorf("вывод статуса: %w", err)
	}
	c, runErr := process(ctx, h, out, detector, publisher)
	if publisher != nil {
		status := c.status(false)
		switch {
		case runErr == nil && pcapPath != "":
			status.Result = monitor.Complete
		case runErr != nil && !errors.Is(runErr, context.Canceled):
			status.Result = monitor.Failed
		}
		publisher.Status(status)
	}
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	_, printErr := fmt.Fprintf(out, "Прочитано: %d | TCP: %d | Неподдерживаемые: %d | Повреждённые: %d | Усечённые: %d\n", c.Read, c.TCP, c.Unsupported, c.Malformed, c.Truncated)
	if publisher != nil {
		_, err := fmt.Fprintf(out, "Не доставлено алертов: %d\n", publisher.Dropped())
		printErr = errors.Join(printErr, err)
	}
	if detector != nil {
		stats := detector.Stats()
		_, err := fmt.Fprintf(out, "Алерты: %d | Без окна из-за лимита: %d | Убывающие отметки времени: %d\n", c.Alerts, stats.StateLimit, stats.OutOfOrder)
		printErr = errors.Join(printErr, err)
	}
	if pcapPath != "" {
		return errors.Join(runErr, printErr)
	}
	stats, statsErr := h.Stats()
	if statsErr == nil {
		_, err = fmt.Fprintf(out, "libpcap: получено=%d | потеряно в буфере=%d | потеряно интерфейсом=%d\n", stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
		printErr = errors.Join(printErr, err)
	} else {
		statsErr = fmt.Errorf("статистика libpcap: %w", statsErr)
	}
	return errors.Join(runErr, printErr, statsErr)
}

func process(ctx context.Context, reader packetReader, out io.Writer, detector *detect.TCP, publisher *monitor.Publisher) (counts, error) {
	var c counts
	var nextReport time.Time
	for {
		if err := ctx.Err(); err != nil {
			return c, err
		}
		if publisher != nil {
			if now := time.Now(); !now.Before(nextReport) {
				publisher.Status(c.status(true))
				nextReport = now.Add(time.Second)
			}
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
		if detector == nil {
			// shortcut: диагностический вывод каждого пакета подходит только для небольшого трафика.
			if _, err := fmt.Fprintf(out, "%s %s -> %s flags=%s\n", tcp.Time.Format(time.RFC3339Nano), tcp.Source, tcp.Destination, tcp.Flags); err != nil {
				return c, fmt.Errorf("вывод TCP: %w", err)
			}
			continue
		}
		for _, match := range detector.Observe(tcp) {
			alert := monitor.Alert{
				Time: tcp.Time, Source: tcp.Source, Destination: tcp.Destination,
				SID: match.SID, Revision: match.Revision, Message: match.Message, Flags: tcp.Flags.String(),
				Threshold: match.Threshold.Type, Count: match.Count, Limit: match.Threshold.Count, Seconds: match.Threshold.Seconds,
			}
			if _, err := fmt.Fprintf(out, "АЛЕРТ %s [%d:%d] %q %s -> %s flags=%s совпадений=%d окно=%dс\n",
				alert.Time.Format(time.RFC3339Nano), alert.SID, alert.Revision, alert.Message,
				alert.Source, alert.Destination, alert.Flags, alert.Count, alert.Seconds); err != nil {
				return c, fmt.Errorf("вывод алерта: %w", err)
			}
			c.Alerts++
			if publisher != nil {
				publisher.Alert(alert)
			}
		}
	}
}
