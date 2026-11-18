package detect

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/wild-sergunys/absolert/internal/packet"
	"github.com/wild-sergunys/absolert/internal/rules"
)

const maxWindows = 4096

type tcpRule struct {
	rules.Rule
	ignored packet.Flags
	window  time.Duration
}

type windowKey struct {
	sid    uint32
	source netip.Addr
}

type thresholdWindow struct {
	end   time.Time
	count uint32
}

type Stats struct {
	StateLimit uint64
	OutOfOrder uint64
}

type Match struct {
	rules.Rule
	Count uint32
}

type TCP struct {
	home        netip.Prefix
	rules       []tcpRule
	windows     map[windowKey]thresholdWindow
	lastPacket  time.Time
	nextCleanup time.Time
	stats       Stats
}

func NewTCP(loaded []rules.Rule, home netip.Prefix) (*TCP, error) {
	if !home.IsValid() || !home.Addr().Is4() || home.Bits() == 0 {
		return nil, fmt.Errorf("HOME_NET: нужна IPv4-подсеть с непустым EXTERNAL_NET")
	}
	if len(loaded) == 0 {
		return nil, fmt.Errorf("нет активных правил")
	}
	detector := &TCP{home: home.Masked(), windows: make(map[windowKey]thresholdWindow)}
	for _, rule := range loaded {
		threshold := rule.Threshold
		if !rule.ToServer || rule.Source.Network != "$EXTERNAL_NET" || rule.Destination.Network != "$HOME_NET" {
			return nil, fmt.Errorf("SID %d: исполнитель поддерживает только входящий flow:to_server из EXTERNAL_NET в HOME_NET", rule.SID)
		}
		if !threshold.Supported() {
			return nil, fmt.Errorf("SID %d: нужен threshold типа both или limit с track by_src и положительными count и seconds", rule.SID)
		}
		compiled := tcpRule{Rule: rule, window: time.Duration(threshold.Seconds) * time.Second}
		switch rule.Flags {
		case "S":
		case "S,12":
			compiled.ignored = packet.CWR | packet.ECE
		default:
			return nil, fmt.Errorf("SID %d: неподдерживаемые флаги %q", rule.SID, rule.Flags)
		}
		detector.rules = append(detector.rules, compiled)
	}
	return detector, nil
}

func (detector *TCP) Stats() Stats { return detector.stats }

func (detector *TCP) Observe(observation packet.TCP) []Match {
	now := observation.Time
	if now.Before(detector.lastPacket) {
		detector.stats.OutOfOrder++
		return nil
	}
	detector.lastPacket = now
	if !now.Before(detector.nextCleanup) {
		for key, window := range detector.windows {
			if now.After(window.end) {
				delete(detector.windows, key)
			}
		}
		detector.nextCleanup = now.Add(time.Second)
	}

	source := observation.Source.Addr()
	if !source.Is4() || detector.home.Contains(source) || !detector.home.Contains(observation.Destination.Addr()) {
		return nil
	}

	var matches []Match
	// shortcut: входящий начальный SYN задаёт направление; для других flow-условий нужен учёт соединений.
	flags := observation.Flags & 0xff
	for _, rule := range detector.rules {
		if flags&^rule.ignored != packet.SYN ||
			!containsPort(rule.Source.Ports, observation.Source.Port()) ||
			!containsPort(rule.Destination.Ports, observation.Destination.Port()) {
			continue
		}
		key := windowKey{sid: rule.SID, source: source}
		window, exists := detector.windows[key]
		if !exists && len(detector.windows) == maxWindows {
			detector.stats.StateLimit++
			continue
		}
		if !exists || now.After(window.end) {
			window = thresholdWindow{end: now.Add(rule.window)}
		}
		if window.count == rule.Threshold.Count {
			continue
		}
		window.count++
		detector.windows[key] = window
		if rule.Threshold.Type == "limit" || window.count == rule.Threshold.Count {
			matches = append(matches, Match{Rule: rule.Rule, Count: window.count})
		}
	}
	return matches
}

func containsPort(ports rules.PortRange, port uint16) bool {
	return ports.First <= port && port <= ports.Last
}
