// Package rules загружает явно ограниченный поднабор формата правил Suricata.
package rules

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxFileSize = 1 << 20
	maxLineSize = 64 << 10
	maxRules    = 1024
)

// PortRange задаёт включительный диапазон, в том числе 0–65535 для any.
type PortRange struct{ First, Last uint16 }
type Endpoint struct {
	Network string
	Ports   PortRange
}
type Threshold struct {
	Type, Track    string
	Count, Seconds uint32
}

// Rule — проверенное описание условий, а не исполняемый детектор.
// Сетевые переменные разрешаются отдельно при подготовке движка.
type Rule struct {
	SID, Revision            uint32
	Message, Class, Metadata string
	Source, Destination      Endpoint
	Flags                    string
	ToServer                 bool
	Threshold                Threshold
}

// Load отклоняет файл целиком при любой ошибке; строки отключённых правил — комментарии.
// Лимиты ограничивают память при чтении недоверенных файлов правил.
func Load(reader io.Reader) ([]Rule, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("чтение правил: %w", err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("файл правил превышает %d байт", maxFileSize)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxLineSize)
	var result []Rule
	seen := make(map[uint32]bool)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		r, err := parseRule(text)
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", line, err)
		}
		if seen[r.SID] {
			return nil, fmt.Errorf("строка %d: повторный SID %d", line, r.SID)
		}
		if len(result) == maxRules {
			return nil, fmt.Errorf("строка %d: превышен предел %d правил", line, maxRules)
		}
		seen[r.SID] = true
		result = append(result, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("строка %d: чтение правила: %w", line+1, err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("нет активных правил")
	}
	return result, nil
}

func parseRule(text string) (Rule, error) {
	var r Rule
	if !utf8.ValidString(text) || strings.ContainsFunc(text, func(c rune) bool { return unicode.IsControl(c) && c != '\t' }) {
		return r, fmt.Errorf("недопустимые символы в правиле")
	}
	start := strings.IndexByte(text, '(')
	if start < 0 || !strings.HasSuffix(text, ")") {
		return r, fmt.Errorf("ожидаются заголовок и условия в скобках")
	}
	header := strings.Fields(text[:start])
	if len(header) != 7 || header[0] != "alert" || header[1] != "tcp" || header[4] != "->" {
		return r, fmt.Errorf("поддерживается заголовок alert tcp SRC PORT -> DST PORT")
	}
	var err error
	if r.Source, err = parseEndpoint(header[2], header[3]); err != nil {
		return r, err
	}
	if r.Destination, err = parseEndpoint(header[5], header[6]); err != nil {
		return r, err
	}
	options, err := splitOptions(text[start+1 : len(text)-1])
	if err != nil {
		return r, err
	}
	seen := make(map[string]bool)
	for _, option := range options {
		key, value, ok := strings.Cut(option, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return Rule{}, fmt.Errorf("ожидается непустая опция keyword:value")
		}
		if seen[key] {
			return Rule{}, fmt.Errorf("повторная опция %q", key)
		}
		seen[key] = true
		switch key {
		case "msg":
			r.Message, err = quotedMessage(value)
		case "sid":
			r.SID, err = positiveNumber(value)
		case "rev":
			r.Revision, err = positiveNumber(value)
		case "flow":
			if value != "to_server" {
				err = fmt.Errorf("поддерживается только flow:to_server")
			} else {
				r.ToServer = true
			}
		case "flags":
			if value != "S" && value != "S,12" {
				err = fmt.Errorf("поддерживаются только flags:S и flags:S,12")
			} else {
				r.Flags = value
			}
		case "threshold":
			r.Threshold, err = parseThreshold(value)
		case "classtype":
			if len(strings.Fields(value)) != 1 {
				err = fmt.Errorf("ожидается одно имя classtype")
			} else {
				r.Class = value
			}
		case "metadata":
			r.Metadata = value
		default:
			err = fmt.Errorf("неподдерживаемая опция %q", key)
		}
		if err != nil {
			return Rule{}, fmt.Errorf("опция %s: %w", key, err)
		}
	}
	for _, key := range []string{"msg", "sid", "rev", "flow", "flags", "threshold", "classtype"} {
		if !seen[key] {
			return Rule{}, fmt.Errorf("для текущего поднабора обязательна опция %s", key)
		}
	}
	return r, nil
}

// Разделитель внутри кавычек не завершает опцию; экранирование проверяется отдельно.
func splitOptions(text string) ([]string, error) {
	var result []string
	start := 0
	quoted, escaped := false, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if escaped {
			escaped = false
			continue
		}
		if quoted && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			continue
		}
		if c == ';' && !quoted {
			option := strings.TrimSpace(text[start:i])
			if option == "" {
				return nil, fmt.Errorf("пустая опция")
			}
			result = append(result, option)
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, fmt.Errorf("незавершённая строка в кавычках")
	}
	if strings.TrimSpace(text[start:]) != "" {
		return nil, fmt.Errorf("каждая опция должна завершаться точкой с запятой")
	}
	return result, nil
}

func quotedMessage(value string) (string, error) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", fmt.Errorf("msg должен быть строкой в двойных кавычках")
	}
	var out strings.Builder
	for i := 1; i < len(value)-1; i++ {
		c := value[i]
		switch c {
		case '\\':
			i++
			if i >= len(value)-1 || (value[i] != '\\' && value[i] != '"') {
				return "", fmt.Errorf("неподдерживаемое экранирование msg")
			}
			c = value[i]
		case '"':
			return "", fmt.Errorf("неэкранированная кавычка в msg")
		}
		out.WriteByte(c)
	}
	if out.Len() == 0 || strings.ContainsFunc(out.String(), unicode.IsControl) {
		return "", fmt.Errorf("msg пуст или содержит управляющие символы")
	}
	return out.String(), nil
}

func parseEndpoint(network, ports string) (Endpoint, error) {
	if network != "any" && network != "$HOME_NET" && network != "$EXTERNAL_NET" {
		return Endpoint{}, fmt.Errorf("поддерживаются только сети any, $HOME_NET и $EXTERNAL_NET")
	}
	if ports == "any" {
		return Endpoint{network, PortRange{0, 65535}}, nil
	}
	first, last, ok := strings.Cut(ports, ":")
	if !ok {
		last = first
	}
	a, errA := strconv.ParseUint(first, 10, 16)
	b, errB := strconv.ParseUint(last, 10, 16)
	if errA != nil || errB != nil || a > b {
		return Endpoint{}, fmt.Errorf("недопустимый порт или включительный диапазон")
	}
	return Endpoint{network, PortRange{uint16(a), uint16(b)}}, nil
}

func positiveNumber(value string) (uint32, error) {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("ожидается целое число от 1 до 4294967295")
	}
	return uint32(n), nil
}

func parseThreshold(value string) (Threshold, error) {
	var result Threshold
	seen := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		fields := strings.Fields(part)
		if len(fields) != 2 || seen[fields[0]] {
			return result, fmt.Errorf("недопустимый или повторный параметр threshold")
		}
		seen[fields[0]] = true
		var err error
		switch fields[0] {
		case "type":
			result.Type = fields[1]
		case "track":
			result.Track = fields[1]
		case "count":
			result.Count, err = positiveNumber(fields[1])
		case "seconds":
			result.Seconds, err = positiveNumber(fields[1])
		default:
			err = fmt.Errorf("неподдерживаемый параметр threshold")
		}
		if err != nil {
			return result, err
		}
	}
	if len(seen) != 4 || result.Type != "both" || result.Track != "by_src" {
		return result, fmt.Errorf("поддерживается threshold:type both,track by_src,count N,seconds T")
	}
	return result, nil
}
